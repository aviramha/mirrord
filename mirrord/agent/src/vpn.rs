use std::{collections::HashMap, fmt, thread, time::Duration};

use bytes::Bytes;
use mirrord_protocol::vpn::{ClientVpn, ServerVpn};
use socket_stream::SocketStream;
use streammap_ext::StreamMap;
use tokio::{
    io::{self, AsyncWriteExt, ReadHalf, WriteHalf},
    select,
    sync::mpsc::{self, error::SendError, Receiver, Sender},
    time,
};
use tokio_stream::StreamExt;
use tokio_util::io::ReaderStream;
pub(crate) use udp::UdpOutgoingApi;

use crate::{
    error::Result,
    util::run_thread_in_namespace,
    watched_task::{TaskStatus, WatchedTask},
};

/// An interface for a background task handling [`LayerTcpOutgoing`] messages.
/// Each agent client has their own independent instance (neither this wrapper nor the background
/// task are shared).
pub(crate) struct VpnApi {
    /// Holds the thread in which [`TcpOutgoingTask`] is running.
    _task: thread::JoinHandle<()>,

    /// Status of the [`TcpOutgoingTask`].
    task_status: TaskStatus,

    /// Sends the layer messages to the [`TcpOutgoingTask`].
    layer_tx: Sender<ServerVpn>,

    /// Reads the daemon messages from the [`TcpOutgoingTask`].
    daemon_rx: Receiver<ClientVpn>,
}

impl VpnApi {
    const TASK_NAME: &'static str = "Vpn";

    /// Spawns a new background task for handling `outgoing` feature and creates a new instance of
    /// this struct to serve as an interface.
    ///
    /// # Params
    ///
    /// * `pid` - process id of the agent's target container
    #[tracing::instrument(level = "trace")]
    pub(crate) fn new(pid: Option<u64>) -> Self {
        let (layer_tx, layer_rx) = mpsc::channel(1000);
        let (daemon_tx, daemon_rx) = mpsc::channel(1000);

        let watched_task = WatchedTask::new(
            Self::TASK_NAME,
            VpnTask::new(pid, layer_rx, daemon_tx).run(),
        );
        let task_status = watched_task.status();
        let task = run_thread_in_namespace(
            watched_task.start(),
            Self::TASK_NAME.to_string(),
            pid,
            "net",
        );

        Self {
            _task: task,
            task_status,
            layer_tx,
            daemon_rx,
        }
    }

    /// Sends the [`LayerTcpOutgoing`] message to the background task.
    #[tracing::instrument(level = "trace", skip(self))]
    pub(crate) async fn layer_message(&mut self, message: ClientVpn) -> Result<()> {
        if self.layer_tx.send(message).await.is_ok() {
            Ok(())
        } else {
            Err(self.task_status.unwrap_err().await)
        }
    }

    /// Receives a [`DaemonTcpOutgoing`] message from the background task.
    pub(crate) async fn daemon_message(&mut self) -> Result<ServerVpn> {
        match self.daemon_rx.recv().await {
            Some(msg) => Ok(msg),
            None => Err(self.task_status.unwrap_err().await),
        }
    }
}

/// Handles outgoing connections for one client (layer).
struct VpnTask {
    pid: Option<u64>,
    layer_rx: Receiver<ClientVpn>,
    daemon_tx: Sender<ServerVpn>,
}

impl fmt::Debug for VpnTask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VpnTask").field("pid", &self.pid).finish()
    }
}

impl VpnTask {
    fn new(pid: Option<u64>, layer_rx: Receiver<ClientVpn>, daemon_tx: Sender<ServerVpn>) -> Self {
        Self {
            pid,
            layer_rx,
            daemon_tx,
        }
    }

    /// Runs this task as long as the channels connecting it with [`TcpOutgoingApi`] are open.
    async fn run(mut self) -> Result<()> {
        loop {
            select! {
                biased;

                message = self.layer_rx.recv() => match message {
                    // We have a message from the layer to be handled.
                    Some(message) => self.handle_layer_msg(message).await?,
                    // Our channel with the layer is closed, this task is no longer needed.
                    None => {
                        tracing::trace!("VpnTask -> Channel with the layer is closed, exiting.");
                        break Ok(());
                    },
                },

                // We have data coming from one of our peers.
                Some((connection_id, remote_read)) = self.readers.next() => {
                    self.handle_connection_read(connection_id, remote_read).await?;
                },
            }
        }
    }

    #[tracing::instrument(
        level = "trace",
        skip(read),
        fields(read = ?read.as_ref().map(|res| res.as_ref().map(|bytes| bytes.len()))),
        ret,
        err(Debug)
    )]
    async fn handle_connection_read(
        &mut self,
        connection_id: ConnectionId,
        read: Option<io::Result<Bytes>>,
    ) -> Result<(), SendError<DaemonTcpOutgoing>> {
        match read {
            // New bytes came in from a peer connection.
            // We pass them to the layer.
            Some(Ok(read)) => {
                let message = DaemonTcpOutgoing::Read(Ok(DaemonRead {
                    connection_id,
                    bytes: read.to_vec(),
                }));

                self.daemon_tx.send(message).await?;
            }

            // An error occurred when reading from a peer connection.
            // We remove both io halves and inform the layer that the connection is closed.
            // We remove the reader, because otherwise the `StreamMap` will produce an extra `None`
            // item from the related stream.
            Some(Err(error)) => {
                tracing::trace!(
                    ?error,
                    connection_id,
                    "Reading from peer connection failed, sending close message.",
                );

                self.readers.remove(&connection_id);
                self.writers.remove(&connection_id);

                let daemon_message = DaemonTcpOutgoing::Close(connection_id);
                self.daemon_tx.send(daemon_message).await?;
            }

            // EOF occurred in one of peer connections.
            // We send 0-sized read to the layer to inform about the shutdown condition.
            // Reader removal is handled internally by the `StreamMap`.
            None => {
                tracing::trace!(
                    connection_id,
                    "Peer connection shutdown, sending 0-sized read message.",
                );

                let daemon_message = DaemonTcpOutgoing::Read(Ok(DaemonRead {
                    connection_id,
                    bytes: vec![],
                }));

                self.daemon_tx.send(daemon_message).await?;

                // If the writing half is not found, it means that the layer has already shut down
                // its side of the connection. We send a closing message to clean
                // everything up.
                if !self.writers.contains_key(&connection_id) {
                    tracing::trace!(
                        connection_id,
                        "Layer connection is shut down as well, sending close message.",
                    );

                    self.daemon_tx
                        .send(DaemonTcpOutgoing::Close(connection_id))
                        .await?;
                }
            }
        }

        Ok(())
    }

    #[tracing::instrument(level = "trace", ret, err(Debug))]
    async fn handle_layer_msg(&mut self, message: ClientVpn) -> Result<(), SendError<ServerVpn>> {
        match message {
            // We make connection to the requested address, split the stream into halves with
            // `io::split`, and put them into respective maps.
            ClientVpn::GetNetworkConfiguration => {
                // Try to find an interface that matches the local ip we have.
                let interface = nix::ifaddrs::getifaddrs()?
                    .find(|iface| (iface.interface_name == "eth0"))
                    .unwrap();
                self.daemon_tx(ServerVpn::NetworkConfiguration(NetworkConfiguration {
                    ip: interface.address.into(),
                    net_mask: interface.netmask.unwrap().into(),
                    gateway: interface.destination.unwrap().into(),
                }))
                .await?;
            },
            _ => unimplemented!("Aaa")
        }

        Ok(())
    }
}
