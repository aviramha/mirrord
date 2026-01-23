use std::{io, ops::ControlFlow, time::Duration};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncWrite, BufReader, BufWriter},
    net::{
        TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    time::interval,
};
use tracing::{debug, trace, warn};

use crate::{
    ProxyMessage,
    background_tasks::{BackgroundTask, MessageBus, RestartableBackgroundTask},
};

/// Message sent to the debugger connection task.
#[derive(Debug, Clone)]
pub enum DebuggerConnectionMessage {
    /// Update the list of connected layers.
    LayersUpdate(Vec<LayerInfo>),
}

/// Process information for the debugger (serializable version).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u64,
    pub name: String,
    pub cmdline: Vec<String>,
}

impl From<&mirrord_intproxy_protocol::ProcessInfo> for ProcessInfo {
    fn from(info: &mirrord_intproxy_protocol::ProcessInfo) -> Self {
        Self {
            pid: info.pid as u64,
            name: info.name.clone(),
            cmdline: info.cmdline.clone(),
        }
    }
}

/// Information about a layer connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerInfo {
    pub layer_id: u64,
    pub process_info: ProcessInfo,
}

/// Messages sent to the debugger server.
#[derive(Debug, Clone, Serialize, Deserialize)]
enum IntproxyToDebugger {
    Register {
        intproxy_id: String,
        port: u16,
    },
    LayerUpdate {
        intproxy_id: String,
        layers: Vec<LayerInfo>,
    },
    Heartbeat {
        intproxy_id: String,
    },
}

/// Messages received from the debugger server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
enum DebuggerToIntproxy {
    RegisterAck,
    QueryLayers,
    Ping,
}

/// Errors that can occur in the debugger connection.
#[derive(Error, Debug)]
pub enum DebuggerConnectionError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("Max reconnection attempts exceeded")]
    MaxRetriesExceeded,
}

/// Background task that maintains a connection to the debugger server.
pub struct DebuggerConnection {
    debugger_addr: String,
    intproxy_id: String,
    port: u16,
    reader: Option<BufReader<OwnedReadHalf>>,
    writer: Option<BufWriter<OwnedWriteHalf>>,
    reconnect_attempts: u32,
    current_layers: Vec<LayerInfo>,
}

impl DebuggerConnection {
    /// Create a new debugger connection task.
    pub fn new(debugger_addr: String, port: u16) -> Self {
        // Generate intproxy ID: hostname-port-random
        let hostname = hostname::get()
            .unwrap_or_else(|_| "unknown".into())
            .to_string_lossy()
            .to_string();
        let random_id: u32 = rand::random();
        let intproxy_id = format!("{}-{}-{:x}", hostname, port, random_id);

        debug!("Creating debugger connection for intproxy {}", intproxy_id);

        Self {
            debugger_addr,
            intproxy_id,
            port,
            reader: None,
            writer: None,
            reconnect_attempts: 0,
            current_layers: Vec::new(),
        }
    }

    /// Connect or reconnect to the debugger server.
    async fn connect(&mut self) -> io::Result<()> {
        debug!("Connecting to debugger at {}", self.debugger_addr);

        let stream = TcpStream::connect(&self.debugger_addr).await?;
        let (read_half, write_half) = stream.into_split();

        let mut reader = BufReader::new(read_half);
        let mut writer = BufWriter::new(write_half);

        // Send registration message
        let register_msg = IntproxyToDebugger::Register {
            intproxy_id: self.intproxy_id.clone(),
            port: self.port,
        };

        Self::write_message(&mut writer, &register_msg).await?;

        // Wait for acknowledgment
        let _ack: DebuggerToIntproxy = Self::read_message(&mut reader).await?;

        debug!("Successfully registered with debugger");

        self.reader = Some(reader);
        self.writer = Some(writer);
        self.reconnect_attempts = 0;

        Ok(())
    }

    /// Send layer update to the debugger.
    async fn send_layer_update(&mut self) -> io::Result<()> {
        if let Some(ref mut writer) = self.writer {
            let update_msg = IntproxyToDebugger::LayerUpdate {
                intproxy_id: self.intproxy_id.clone(),
                layers: self.current_layers.clone(),
            };

            Self::write_message(writer, &update_msg).await?;
            trace!("Sent layer update to debugger");
        }

        Ok(())
    }

    /// Send heartbeat to the debugger.
    async fn send_heartbeat(&mut self) -> io::Result<()> {
        if let Some(ref mut writer) = self.writer {
            let heartbeat_msg = IntproxyToDebugger::Heartbeat {
                intproxy_id: self.intproxy_id.clone(),
            };

            Self::write_message(writer, &heartbeat_msg).await?;
            trace!("Sent heartbeat to debugger");
        }

        Ok(())
    }

    /// Read a length-prefixed JSON message.
    async fn read_message<R, T>(reader: &mut R) -> io::Result<T>
    where
        R: AsyncRead + Unpin,
        T: for<'de> Deserialize<'de>,
    {
        use tokio::io::AsyncReadExt;

        let len = reader.read_u32().await?;
        let mut buf = vec![0u8; len as usize];
        reader.read_exact(&mut buf).await?;

        serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Write a length-prefixed JSON message.
    async fn write_message<W, T>(writer: &mut W, message: &T) -> io::Result<()>
    where
        W: AsyncWrite + Unpin,
        T: Serialize,
    {
        use tokio::io::AsyncWriteExt;

        let bytes = serde_json::to_vec(message)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        writer.write_u32(bytes.len() as u32).await?;
        writer.write_all(&bytes).await?;
        writer.flush().await
    }
}

impl BackgroundTask for DebuggerConnection {
    type Error = DebuggerConnectionError;
    type MessageIn = DebuggerConnectionMessage;
    type MessageOut = ProxyMessage;

    async fn run(&mut self, message_bus: &mut MessageBus<Self>) -> Result<(), Self::Error> {
        // Initial connection
        self.connect().await?;

        let mut heartbeat_interval = interval(Duration::from_secs(10));

        loop {
            tokio::select! {
                // Receive message from intproxy main loop
                msg = message_bus.recv() => {
                    match msg {
                        Some(DebuggerConnectionMessage::LayersUpdate(layers)) => {
                            self.current_layers = layers;
                            self.send_layer_update().await?;
                        }
                        None => {
                            debug!("Debugger connection message bus closed, exiting");
                            break Ok(());
                        }
                    }
                }

                // Send periodic heartbeat
                _ = heartbeat_interval.tick() => {
                    self.send_heartbeat().await?;
                }
            }
        }
    }
}

impl RestartableBackgroundTask for DebuggerConnection {
    async fn restart(
        &mut self,
        error: Self::Error,
        _message_bus: &mut MessageBus<Self>,
    ) -> ControlFlow<Self::Error> {
        const MAX_RECONNECT_ATTEMPTS: u32 = 10;

        warn!("Debugger connection error: {}", error);

        if self.reconnect_attempts >= MAX_RECONNECT_ATTEMPTS {
            warn!("Max reconnection attempts reached for debugger");
            return ControlFlow::Break(DebuggerConnectionError::MaxRetriesExceeded);
        }

        // Exponential backoff: 1s, 2s, 4s, 8s, 16s (max)
        let delay_secs = 2u64.pow(self.reconnect_attempts.min(4));
        debug!(
            "Reconnecting to debugger in {} seconds (attempt {})",
            delay_secs,
            self.reconnect_attempts + 1
        );

        tokio::time::sleep(Duration::from_secs(delay_secs)).await;

        self.reconnect_attempts += 1;
        self.reader = None;
        self.writer = None;

        ControlFlow::Continue(())
    }
}
