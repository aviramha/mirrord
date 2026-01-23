use std::{collections::HashMap, net::SocketAddr};

use axum::{
    Json, Router,
    extract::{Path, Query, State, WebSocketUpgrade, ws::WebSocket},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
};
use tokio::{net::TcpListener, sync::broadcast};
use tracing::{debug, error, info, trace, warn};

use super::protocol::MessageLog;

use super::{connection::handle_intproxy_connection, state::DebuggerState};

/// Shared server state.
#[derive(Clone)]
struct ServerState {
    token: String,
    debugger_state: DebuggerState,
}

/// Start the debugger server.
///
/// Returns (HTTP address for browser, intproxy TCP address, auth token).
pub async fn start_server() -> Result<(SocketAddr, SocketAddr, String), std::io::Error> {
    // Generate random auth token
    let token = generate_token();

    let debugger_state = DebuggerState::new();

    // Bind HTTP server to localhost on random port
    let http_listener = TcpListener::bind("127.0.0.1:0").await?;
    let http_addr = http_listener.local_addr()?;

    // Bind intproxy TCP listener to localhost on random port
    let intproxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let intproxy_addr = intproxy_listener.local_addr()?;

    info!(
        "Debugger server starting - HTTP: {}, Intproxy: {}",
        http_addr, intproxy_addr
    );

    let server_state = ServerState {
        token: token.clone(),
        debugger_state: debugger_state.clone(),
    };

    // Spawn HTTP server task
    tokio::spawn(run_http_server(http_listener, server_state.clone()));

    // Spawn intproxy connection acceptor
    tokio::spawn(accept_intproxy_connections(
        intproxy_listener,
        debugger_state.clone(),
    ));

    // Spawn periodic cleanup task
    tokio::spawn(periodic_cleanup(debugger_state));

    Ok((http_addr, intproxy_addr, token))
}

/// Run the HTTP/WebSocket server.
async fn run_http_server(listener: TcpListener, state: ServerState) {
    let app = Router::new()
        .route("/", get(index_handler))
        .route("/ws", get(websocket_handler))
        .route("/logs/{layer_id}", get(logs_handler))
        .with_state(state);

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

/// Handler for getting message logs for a layer (requires token authentication).
async fn logs_handler(
    Path(layer_id): Path<u64>,
    Query(params): Query<HashMap<String, String>>,
    State(state): State<ServerState>,
) -> Result<Json<Vec<MessageLog>>, StatusCode> {
    let provided_token = params.get("token");

    if provided_token != Some(&state.token) {
        warn!("Unauthorized logs access attempt");
        return Err(StatusCode::FORBIDDEN);
    }

    let logs = state.debugger_state.get_layer_logs(layer_id).await;
    Ok(Json(logs))
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
