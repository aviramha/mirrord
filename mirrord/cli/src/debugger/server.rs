use std::{collections::HashMap, net::SocketAddr};

use axum::{
    Router,
    extract::{Query, State, WebSocketUpgrade, ws::WebSocket},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
};
use tokio::{net::TcpListener, sync::broadcast};
use tracing::{debug, error, info, trace, warn};

use super::{connection::handle_intproxy_connection, state::DebuggerState};

/// Shared server state.
#[derive(Clone)]
struct ServerState {
    token: String,
    debugger_state: DebuggerState,
}

/// Start the debugger server.
///
/// Returns the bound address and authentication token.
pub async fn start_server() -> Result<(SocketAddr, String), std::io::Error> {
    // Generate random auth token
    let token = generate_token();

    // Bind to localhost on random port
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    info!("Debugger server starting on {}", addr);

    let debugger_state = DebuggerState::new();

    let server_state = ServerState {
        token: token.clone(),
        debugger_state: debugger_state.clone(),
    };

    // Spawn HTTP server task
    tokio::spawn(run_http_server(addr, server_state.clone()));

    // Spawn intproxy connection acceptor
    tokio::spawn(accept_intproxy_connections(
        listener,
        debugger_state.clone(),
    ));

    // Spawn periodic cleanup task
    tokio::spawn(periodic_cleanup(debugger_state));

    Ok((addr, token))
}

/// Run the HTTP/WebSocket server.
async fn run_http_server(addr: SocketAddr, state: ServerState) {
    let app = Router::new()
        .route("/", get(index_handler))
        .route("/ws", get(websocket_handler))
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind HTTP server: {}", e);
            return;
        }
    };

    if let Err(e) = axum::serve(listener, app).await {
        error!("HTTP server error: {}", e);
    }
}

/// Handler for the index page (requires token authentication).
async fn index_handler(
    Query(params): Query<HashMap<String, String>>,
    State(state): State<ServerState>,
) -> Result<Html<&'static str>, StatusCode> {
    let provided_token = params.get("token");

    if provided_token != Some(&state.token) {
        warn!("Unauthorized access attempt to debugger UI");
        return Err(StatusCode::FORBIDDEN);
    }

    Ok(Html(include_str!("ui/index.html")))
}

/// Handler for WebSocket connections (requires token authentication).
async fn websocket_handler(
    Query(params): Query<HashMap<String, String>>,
    State(state): State<ServerState>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    let provided_token = params.get("token");

    if provided_token != Some(&state.token) {
        warn!("Unauthorized WebSocket connection attempt");
        return StatusCode::FORBIDDEN.into_response();
    }

    ws.on_upgrade(move |socket| handle_websocket(socket, state.debugger_state))
        .into_response()
}

/// Handle an authenticated WebSocket connection.
async fn handle_websocket(mut socket: WebSocket, state: DebuggerState) {
    debug!("New WebSocket client connected");

    // Send initial state
    let snapshot = state.snapshot().await;
    if let Ok(json) = serde_json::to_string(&snapshot) {
        if socket
            .send(axum::extract::ws::Message::Text(json.into()))
            .await
            .is_err()
        {
            debug!("Failed to send initial state to WebSocket client");
            return;
        }
    }

    // Subscribe to updates
    let mut rx = state.subscribe();

    loop {
        tokio::select! {
            // Receive update from state
            update = rx.recv() => {
                match update {
                    Ok(state_update) => {
                        if let Ok(json) = serde_json::to_string(&state_update) {
                            if socket.send(axum::extract::ws::Message::Text(json.into())).await.is_err() {
                                debug!("WebSocket client disconnected");
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(skipped)) => {
                        warn!("WebSocket client lagged, skipped {} updates", skipped);
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        debug!("Update channel closed");
                        break;
                    }
                }
            }

            // Receive message from client (currently unused, but keeps connection alive)
            msg = socket.recv() => {
                if msg.is_none() {
                    debug!("WebSocket client disconnected");
                    break;
                }
            }
        }
    }

    debug!("WebSocket client handler exiting");
}

/// Accept incoming TCP connections from intproxies.
async fn accept_intproxy_connections(listener: TcpListener, state: DebuggerState) {
    loop {
        match listener.accept().await {
            Ok((stream, addr)) => {
                debug!("Accepted intproxy connection from {}", addr);
                let state = state.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_intproxy_connection(stream, state).await {
                        debug!("Intproxy connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept intproxy connection: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        }
    }
}

/// Periodically clean up stale intproxies.
async fn periodic_cleanup(state: DebuggerState) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(10));

    loop {
        interval.tick().await;
        trace!("Running periodic cleanup");
        state.cleanup_stale().await;
    }
}

/// Generate a random authentication token.
fn generate_token() -> String {
    use rand::Rng;
    rand::rng().random::<u64>().to_string()
}
