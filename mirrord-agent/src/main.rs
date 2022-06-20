#![feature(result_option_inspect)]
#![feature(never_type)]

use std::{
    borrow::Borrow,
    collections::HashSet,
    hash::{Hash, Hasher},
    net::{Ipv4Addr, SocketAddrV4},
};

use actix_codec::Framed;
use error::AgentError;
use file::FileManager;
use futures::{stream::FuturesUnordered, SinkExt};
use mirrord_protocol::{
    tcp::{DaemonTcp, LayerTcp},
    ClientMessage, ConnectionID, DaemonCodec, DaemonMessage, Port,
};
use tokio::{
    net::{TcpListener, TcpStream},
    select,
    sync::mpsc::{self, Receiver, Sender},
};
use tokio_stream::StreamExt;
use tracing::{debug, error, info, trace};
use tracing_subscriber::prelude::*;

mod cli;
mod error;
mod file;
mod runtime;
mod sniffer;
mod util;

use cli::parse_args;
use sniffer::{Enabled, SnifferCommand, SnifferOutput, TCPConnectionSniffer, TCPSnifferAPI};
use util::{IndexAllocator, Subscriptions};

use crate::runtime::get_container_pid;

#[derive(Debug)]
struct State {
    pub agents: HashSet<AgentID>,
    index_allocator: IndexAllocator<AgentID>,
}

impl State {
    pub fn new() -> State {
        State {
            agents: HashSet::new(),
            index_allocator: IndexAllocator::new(),
        }
    }

    pub fn generate_id(&mut self) -> Option<AgentID> {
        self.index_allocator.next_index()
    }

    pub fn remove_agent(&mut self, agent_id: AgentID) {
        self.agents.remove(&agent_id);
        self.index_allocator.free_index(agent_id)
    }
}

struct AgentConnectionHandler {
    id: AgentID,
    file_manager: FileManager,
    stream: Framed<TcpStream, DaemonCodec>,
    tcp_sniffer_api: TCPSnifferAPI<Enabled>,
}

impl AgentConnectionHandler {
    /// A loop that handles agent connection and state. Brekas upon receiver/sender drop.
    pub async fn start(
        id: AgentID,
        stream: TcpStream,
        pid: Option<u64>,
        sniffer_command_sender: Sender<SnifferCommand>,
    ) -> Result<(), AgentError> {
        let file_manager = FileManager::new(pid);
        let stream = actix_codec::Framed::new(stream, DaemonCodec::new());
        let (tcp_receiver, tcp_sender) = mpsc::channel(CHANNEL_SIZE);
        let tcp_sniffer_api = TCPSnifferAPI::new(id, sniffer_command_sender, tcp_receiver)
            .enable(tcp_sender)
            .await?;
        let mut agent_handler = AgentConnectionHandler {
            id,
            file_manager,
            stream,
            tcp_sniffer_api,
        };
        agent_handler.handle_loop().await?;
        Ok(())
    }

    async fn handle_loop(&mut self) -> Result<(), AgentError> {
        let mut running = true;
        while running {
            select! {
                message = self.stream.next() => {
                    if let Some(message) = message {
                        running = self.handle_agent_message(message?).await?;
                    } else {
                        debug!("Agent {} disconnected", self.id);
                            break;
                    }
                }
            }
        }
        Ok(())
    }

    /// Handle incoming messages from the agent. Returns False if the agent disconnected.
    async fn handle_agent_message(&mut self, message: ClientMessage) -> Result<bool, AgentError> {
        debug!("agent_handler -> client sent message {:?}", message);
        match message {
            ClientMessage::FileRequest(req) => {
                let response = self.file_manager.handle_message(req)?;
                self.stream
                    .send(DaemonMessage::FileResponse(response))
                    .await
                    .map_err(From::from)?
            }
            ClientMessage::Ping => self
                .stream
                .send(DaemonMessage::Pong)
                .await
                .map_err(From::from)?,
            ClientMessage::Tcp(message) => self.handle_agent_tcp(message).await?,
            ClientMessage::Close => {
                return Ok(false);
            }
        }
        Ok(true)
    }

    async fn handle_agent_tcp(&mut self, message: LayerTcp) -> Result<(), AgentError> {
        match message {
            LayerTcp::PortSubscribe(port) => self.tcp_sniffer_api.subscribe(port).await,
            LayerTcp::ConnectionUnsubscribe(connection_id) => {
                self.tcp_sniffer_api.unsubscribe(connection_id).await
            }
            LayerTcp::PortUnsubscribe(port) => self.tcp_sniffer_api.unsubscribe_port(port).await,
        }
    }
}

async fn start_agent() -> Result<(), AgentError> {
    let args = parse_args();

    let listener = TcpListener::bind(SocketAddrV4::new(
        Ipv4Addr::new(0, 0, 0, 0),
        args.communicate_port,
    ))
    .await?;
    let pid = match (args.container_id, args.container_runtime) {
        (Some(container_id), Some(container_runtime)) => {
            Some(get_container_pid(&container_id, &container_runtime).await?)
        }
        _ => None,
    };

    let mut state = State::new();

    let (sniffer_command_tx, sniffer_command_rx) = mpsc::channel::<SnifferCommand>(1000);

    let sniffer_task = tokio::spawn(TCPConnectionSniffer::start(
        sniffer_command_rx,
        pid,
        args.interface,
    ));

    let agents = FuturesUnordered::new();
    loop {
        select! {
            Ok((stream, addr)) = listener.accept() => {
                debug!("start -> Connection accepted from {:?}", addr);

                if let Some(agent_id) = state.generate_id() {

                    state.agents.insert(agent_id);

                    let agent = tokio::spawn(async move {
                        match AgentConnectionHandler::start(agent_id, stream, pid, sniffer_command_tx.clone()).await {
                            Ok(_) => {
                                debug!("AgentConnectionHandler::start -> Agent {} disconnected", agent_id);
                            }
                            Err(e) => {
                                error!("AgentConnectionHandler::start -> Agent {} disconnected with error: {}", agent_id, e);
                            }
                        }
                        agent_id

                    });
                    agents.push(agent);
                }
                else {
                    error!("start_agent -> Ran out of connections, dropping new connection");
                }

            },
            agent = agents.select_next_some() => {
                let agent_id = agent.await?;
                state.remove_agent(agent_id);
            },
            _ = tokio::time::sleep(std::time::Duration::from_secs(args.communication_timeout.into())) => {
                if state.agents.is_empty() {
                    debug!("start_agent -> main thread timeout, no agents connected");
                    break;
                }
            }
        }
    }

    debug!("start_agent -> shutting down start");
    if !sniffer_command_tx.is_closed() {
        sniffer_command_tx.send(SnifferCommand::Close).await?;
    };

    // To make tasks stop (need to add drain..)
    drop(sniffer_command_tx);
    drop(sniffer_output_rx);

    tokio::time::timeout(std::time::Duration::from_secs(10), packet_task).await???;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), AgentError> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer())
        .with(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    debug!("main -> Initializing mirrord-agent.");

    match start_agent().await {
        Ok(_) => {
            info!("main -> mirrord-agent `start` exiting successfully.")
        }
        Err(fail) => {
            error!(
                "main -> mirrord-agent `start` exiting with error {:#?}",
                fail
            )
        }
    }
    Ok(())
}
