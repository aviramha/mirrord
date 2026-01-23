use std::io;

use tokio::{
    io::{BufReader, BufWriter},
    net::TcpStream,
    time::{Duration, interval},
};
use tracing::trace;

use super::{
    protocol::{DebuggerToIntproxy, IntproxyToDebugger, MessageCodec},
    state::DebuggerState,
};

/// Handle a TCP connection from an intproxy.
pub async fn handle_intproxy_connection(stream: TcpStream, state: DebuggerState) -> io::Result<()> {
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = BufWriter::new(write_half);

    let mut _intproxy_id: Option<String> = None;
    let mut heartbeat_interval = interval(Duration::from_secs(10));

    loop {
        tokio::select! {
            // Read message from intproxy
            message = MessageCodec::read::<_, IntproxyToDebugger>(&mut reader) => {
                let message = message?;
                trace!("Received from intproxy: {:?}", message);

                match message {
                    IntproxyToDebugger::Register { intproxy_id: id, port } => {
                        state.register_intproxy(id.clone(), port).await;
                        _intproxy_id = Some(id);

                        // Send acknowledgment
                        MessageCodec::write(&mut writer, &DebuggerToIntproxy::RegisterAck).await?;
                    }

                    IntproxyToDebugger::LayerUpdate { intproxy_id: id, layers } => {
                        state.update_layers(id, layers).await;
                    }

                    IntproxyToDebugger::Heartbeat { intproxy_id: id } => {
                        state.heartbeat(id).await;
                    }
                }
            }

            // Periodic heartbeat check (future: could send pings to intproxy)
            _ = heartbeat_interval.tick() => {
                trace!("Heartbeat tick (no-op for now)");
            }
        }
    }

    // Connection closed - cleanup handled by periodic task
}
