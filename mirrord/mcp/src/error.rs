use miette::Diagnostic;
use thiserror::Error;

pub type Result<T, E = McpError> = std::result::Result<T, E>;

#[derive(Error, Diagnostic, Debug)]
pub enum McpError {
    #[error("Error starting MCP server: {0}")]
    #[diagnostic(help("Please check the logs for more information."))]
    ServerError(#[from] mcp_server::ServerError),
}
