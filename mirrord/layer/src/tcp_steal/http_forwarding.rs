use mirrord_protocol::tcp::{HttpRequest, HttpResponse};
use thiserror::Error;
use tokio::sync::mpsc::error::SendError;

#[derive(Error, Debug)]
pub(crate) enum HttpForwarderError {
    #[error("HTTP Forwarder: Failed to send connection id for closing with error: {0}.")]
    ConnectionCloseSend(#[from] SendError<u64>),

    #[error("HTTP Forwarder: Failed to send http response to main layer task with error: {0}.")]
    ResponseSend(#[from] SendError<HttpResponse>),

    #[error("HTTP Forwarder: Failed to send http request HTTP client task with error: {0}.")]
    Request2ClientSend(#[from] SendError<HttpRequest>),

    #[error("HTTP Forwarder: Could not send http request to application or receive its response with error: {0}.")]
    HttpForwarding(#[from] hyper::Error),

    #[error("HTTP Forwarder: TCP connection failed with error: {0}.")]
    TcpStream(#[from] std::io::Error),
}
