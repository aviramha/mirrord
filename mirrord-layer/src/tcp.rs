use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use anyhow::Result;
/// TCP Traffic management, common code for stealing & mirroring
use async_trait::async_trait;
use mirrord_protocol::{NewTCPConnection, TCPClose, TCPData};
use tokio::{
    net::TcpStream,
    select,
    sync::mpsc::{channel, Receiver, Sender},
};
use tracing::error;

use crate::{
    common::Listen,
    sockets::{SocketInformation, CONNECTION_QUEUE},
};

const CHANNEL_SIZE: usize = 1024;

#[derive(Debug)]
pub enum TrafficIn {
    Listen(Listen),
    NewConnection(NewTCPConnection),
    Data(TCPData),
    Close(TCPClose),
}

/// To be used by traffic stealer
pub enum TrafficOut {}

/// Struct responsible for managing the traffic handler
/// Communicates using incoming/outgoing channels.
pub struct TCPConfig {
    /// This is reserved for stealing API.
    #[allow(dead_code)]
    outgoing: Sender<TrafficOut>,
    incoming: Receiver<TrafficIn>,
}

/// Struct for controlling the traffic stealing struct.
pub struct TCPApi {
    outgoing: Sender<TrafficIn>,
    /// This is reserved for stealing API.
    #[allow(dead_code)]
    incoming: Receiver<TrafficOut>,
}

impl TCPApi {
    pub async fn send(&self, msg: TrafficIn) -> Result<()> {
        Ok(self.outgoing.send(msg).await?)
    }

    /// This is reserved for stealing API.
    #[allow(dead_code)]
    pub async fn recv(&mut self) -> Option<TrafficOut> {
        self.incoming.recv().await
    }

    pub async fn listen_request(&self, listen: Listen) -> Result<()> {
        self.send(TrafficIn::Listen(listen)).await
    }

    pub async fn new_tcp_connection(&self, conn: NewTCPConnection) -> Result<()> {
        self.send(TrafficIn::NewConnection(conn)).await
    }

    pub async fn tcp_data(&self, data: TCPData) -> Result<()> {
        self.send(TrafficIn::Data(data)).await
    }

    pub async fn tcp_close(&self, close: TCPClose) -> Result<()> {
        self.send(TrafficIn::Close(close)).await
    }
}

#[async_trait]
pub trait TCPHandler {
    /// Create new TCP handler communicating using given TCPConfig
    fn new() -> Self;

    /// Run the TCP Handler, usually as a spawned task.
    async fn run(mut self, mut config: TCPConfig) -> Result<()>
    where
        Self: Sized,
    {
        while self.is_running() {
            select! {
                msg = config.incoming.recv() => {self.handle_incoming_message(msg).await?;},
            }
        }
        Ok(())
    }

    /// Should the run loop keep running
    fn is_running(&mut self) -> bool;

    /// Changes the state so is_running will return False
    fn stop_running(&mut self);

    fn ports(&mut self) -> &HashSet<Listen>;
    fn ports_mut(&mut self) -> &mut HashSet<Listen>;

    async fn handle_incoming_message(&mut self, msg: Option<TrafficIn>) -> Result<()>
    where
        Self: Send,
    {
        if let Some(msg) = msg {
            match msg {
                TrafficIn::NewConnection(conn) => self.handle_new_connection(conn).await?,
                TrafficIn::Data(data) => self.handle_new_data(data).await?,
                TrafficIn::Close(close) => self.handle_close(close).await?,
                TrafficIn::Listen(listen) => self.handle_listen(listen).await?,
            }
        } else {
            self.stop_running();
        }

        Ok(())
    }

    /// Handle NewConnection messages
    async fn handle_new_connection(&mut self, conn: NewTCPConnection) -> Result<()>;

    /// Connects to the local listening socket, add it to the queue and return the stream.
    /// Find better name
    async fn create_local_stream(&mut self, conn: &NewTCPConnection) -> Option<TcpStream> {
        let listen_data = self.ports().get(&conn.destination_port)?;
        let addr = match listen_data.ipv6 {
            false => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen_data.real_port),
            true => SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), listen_data.real_port),
        };

        let info = SocketInformation::new(SocketAddr::new(conn.address, conn.source_port));
        {
            CONNECTION_QUEUE.lock().unwrap().add(&listen_data.fd, info);
        }

        TcpStream::connect(addr)
            .await
            .inspect_err(|err| {
                error!("create local stream failed, couldn't connect {addr:?} with {err:?}")
            })
            .ok()
    }

    /// Handle New Data messages
    async fn handle_new_data(&mut self, data: TCPData) -> Result<()>;

    /// Handle connection close
    async fn handle_close(&mut self, close: TCPClose) -> Result<()>;

    /// Handle listen request
    async fn handle_listen(&mut self, listen: Listen) -> Result<()> {
        self.ports_mut().insert(listen);
        Ok(())
    }
}

pub fn create_tcp_handler<T>() -> (T, TCPApi, TCPConfig)
where
    T: TCPHandler,
{
    let (traffic_in_tx, traffic_in_rx) = channel(CHANNEL_SIZE);
    let (traffic_out_tx, traffic_out_rx) = channel(CHANNEL_SIZE);
    let handler = T::new();
    let control = TCPApi {
        incoming: traffic_out_rx,
        outgoing: traffic_in_tx,
    };
    let config = TCPConfig {
        outgoing: traffic_out_tx,
        incoming: traffic_in_rx,
    };
    (handler, control, config)
}
