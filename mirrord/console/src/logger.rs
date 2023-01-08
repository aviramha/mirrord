use futures::{Sink, SinkExt};
use log::{LevelFilter, Metadata};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{protocol::Message, Error as WsError},
};

use crate::{
    error::{ConsoleError, Result},
    protocol,
};

pub struct ConsoleLogger {
    sender: Sender<protocol::Record>,
}

impl log::Log for ConsoleLogger {
    fn enabled(&self, _metadata: &Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            match self.sender.blocking_send(protocol::Record {
                metadata: protocol::Metadata {
                    level: record.level(),
                    target: record.target().to_string(),
                },
                message: record.args().to_string(),
                module_path: record.module_path().map(|s| s.to_string()),
                file: record.file().map(|s| s.to_string()),
                line: record.line(),
            }) {
                Ok(_) => {}
                Err(e) => {
                    eprintln!("Error sending log message: {e:?}");
                }
            }
        }
    }

    fn flush(&self) {}
}

async fn send_hello<C>(client: &mut C) -> Result<()>
where
    C: Sink<Message, Error = WsError> + std::marker::Unpin,
{
    let hello = protocol::Hello {
        process_info: protocol::ProcessInfo {
            args: std::env::args().collect(),
            env: std::env::vars()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect(),
            cwd: std::env::current_dir()
                .map(|p| p.to_str().map(String::from))
                .unwrap_or(None),
            id: std::process::id().into(),
        },
    };
    let msg = Message::binary(serde_json::to_vec(&hello).unwrap());
    client.send(msg).await?;
    Ok(())
}

async fn logger_task<C>(mut client: C, mut rx: Receiver<protocol::Record>)
where
    C: Sink<Message, Error = WsError> + std::marker::Unpin,
{
    while let Some(msg) = rx.recv().await {
        let msg = Message::binary(serde_json::to_vec(&msg).unwrap());
        let _ = client.feed(msg).await;
    }
}
/// Initializes the logger
/// Connects to the console, and sets the global logger to use it.
pub async fn init_logger(address: &str) -> Result<()> {
    let (tx, rx) = tokio::sync::mpsc::channel(100);
    let (mut client, _) = connect_async(address)
        .await
        .map_err(ConsoleError::ConnectError)?;

    send_hello(&mut client).await?;
    tokio::spawn(async move {
        logger_task(client, rx).await;
    });
    let logger = ConsoleLogger { sender: tx };
    log::set_boxed_logger(Box::new(logger)).map(|()| log::set_max_level(LevelFilter::Trace))?;
    Ok(())
}