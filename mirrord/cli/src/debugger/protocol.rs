use std::io;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Unique identifier for an intproxy instance.
pub type IntproxyId = String;

/// Unique identifier for a layer connection within an intproxy.
pub type LayerId = u64;

/// Direction of a message.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum MessageDirection {
    FromLayer,
    ToLayer,
}

/// A logged message (lightweight, no payload data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageLog {
    pub layer_id: LayerId,
    pub direction: MessageDirection,
    pub message_type: String,
    pub length: usize,
    pub timestamp: u64, // milliseconds since epoch
}

/// Messages sent from intproxy to debugger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IntproxyToDebugger {
    /// Intproxy registers itself with the debugger.
    Register { intproxy_id: IntproxyId, port: u16 },
    /// Update the list of layers connected to this intproxy.
    LayerUpdate {
        intproxy_id: IntproxyId,
        layers: Vec<LayerInfo>,
    },
    /// Periodic heartbeat to indicate the intproxy is still alive.
    Heartbeat { intproxy_id: IntproxyId },
    /// Log a message from/to a layer.
    MessageLog {
        intproxy_id: IntproxyId,
        log: MessageLog,
    },
}

/// Messages sent from debugger to intproxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DebuggerToIntproxy {
    /// Acknowledgment of registration.
    RegisterAck,
    /// Request full layer state (future feature).
    QueryLayers,
    /// Keepalive ping (future feature).
    Ping,
}

/// Process information (serializable version).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u64,
    pub parent_pid: u64,
    pub name: String,
    pub cmdline: Vec<String>,
}

impl From<&mirrord_intproxy_protocol::ProcessInfo> for ProcessInfo {
    fn from(info: &mirrord_intproxy_protocol::ProcessInfo) -> Self {
        Self {
            pid: info.pid as u64,
            parent_pid: info.parent_pid as u64,
            name: info.name.clone(),
            cmdline: info.cmdline.clone(),
        }
    }
}

/// Information about a layer connection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerInfo {
    pub layer_id: LayerId,
    pub process_info: ProcessInfo,
}

/// Length-prefixed message codec for reading and writing JSON messages.
pub struct MessageCodec;

impl MessageCodec {
    /// Read a length-prefixed message from a stream.
    pub async fn read<R: AsyncReadExt + Unpin, T: for<'de> Deserialize<'de>>(
        reader: &mut R,
    ) -> io::Result<T> {
        // Read 4-byte length prefix
        let len = reader.read_u32().await?;

        // Read message bytes
        let mut buf = vec![0u8; len as usize];
        reader.read_exact(&mut buf).await?;

        // Deserialize JSON
        serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Write a length-prefixed message to a stream.
    pub async fn write<W: AsyncWriteExt + Unpin, T: Serialize>(
        writer: &mut W,
        message: &T,
    ) -> io::Result<()> {
        // Serialize to JSON
        let bytes = serde_json::to_vec(message)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        // Write length prefix
        writer.write_u32(bytes.len() as u32).await?;

        // Write message bytes
        writer.write_all(&bytes).await?;

        writer.flush().await
    }
}
