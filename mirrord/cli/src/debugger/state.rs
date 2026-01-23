use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, SystemTime},
};

use chrono::{DateTime, Utc};
use serde::Serialize;
use tokio::sync::{RwLock, broadcast};
use tracing::{debug, trace};

use super::protocol::{IntproxyId, LayerId, LayerInfo, MessageLog};

/// Maximum number of WebSocket clients that can receive broadcast updates.
const BROADCAST_CAPACITY: usize = 16;

/// Duration after which an intproxy is considered stale (no heartbeat).
const STALE_TIMEOUT: Duration = Duration::from_secs(30);

/// Maximum number of messages to keep per layer.
const MAX_MESSAGES_PER_LAYER: usize = 1000;

/// Shared state tracking all intproxy instances and their layers.
#[derive(Clone)]
pub struct DebuggerState {
    inner: Arc<RwLock<StateInner>>,
    update_tx: broadcast::Sender<StateUpdate>,
}

struct StateInner {
    intproxies: HashMap<IntproxyId, IntproxyInfo>,
    /// Message logs per layer (cyclic buffer, max 1000 per layer).
    message_logs: HashMap<LayerId, VecDeque<MessageLog>>,
}

/// Information about a single intproxy instance.
#[derive(Debug, Clone, Serialize)]
pub struct IntproxyInfo {
    pub port: u16,
    pub layers: Vec<LayerInfo>,
    #[serde(with = "chrono::serde::ts_seconds")]
    pub last_heartbeat: DateTime<Utc>,
}

/// Update message broadcast to WebSocket clients.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum StateUpdate {
    /// Full state snapshot.
    Snapshot {
        intproxies: HashMap<IntproxyId, IntproxyInfo>,
    },
    /// New message log for a layer.
    MessageLog {
        layer_id: LayerId,
        log: MessageLog,
    },
}

impl DebuggerState {
    /// Create a new debugger state instance.
    pub fn new() -> Self {
        let (update_tx, _) = broadcast::channel(BROADCAST_CAPACITY);

        Self {
            inner: Arc::new(RwLock::new(StateInner {
                intproxies: HashMap::new(),
                message_logs: HashMap::new(),
            })),
            update_tx,
        }
    }

    /// Register a new intproxy instance.
    pub async fn register_intproxy(&self, id: IntproxyId, port: u16) {
        debug!("Registering intproxy: {} (port {})", id, port);

        let mut inner = self.inner.write().await;
        inner.intproxies.insert(
            id,
            IntproxyInfo {
                port,
                layers: Vec::new(),
                last_heartbeat: Utc::now(),
            },
        );

        drop(inner);
        self.broadcast_update().await;
    }

    /// Update layers for an intproxy.
    pub async fn update_layers(&self, id: IntproxyId, layers: Vec<LayerInfo>) {
        trace!(
            "Updating layers for intproxy {}: {} layers",
            id,
            layers.len()
        );

        let mut inner = self.inner.write().await;
        if let Some(info) = inner.intproxies.get_mut(&id) {
            info.layers = layers;
            info.last_heartbeat = Utc::now();
        }

        drop(inner);
        self.broadcast_update().await;
    }

    /// Record a heartbeat from an intproxy.
    pub async fn heartbeat(&self, id: IntproxyId) {
        trace!("Heartbeat from intproxy {}", id);

        let mut inner = self.inner.write().await;
        if let Some(info) = inner.intproxies.get_mut(&id) {
            info.last_heartbeat = Utc::now();
        }
    }

    /// Log a message from/to a layer.
    pub async fn log_message(&self, log: MessageLog) {
        trace!("Logging message for layer {}", log.layer_id);

        let mut inner = self.inner.write().await;
        let logs = inner.message_logs.entry(log.layer_id).or_insert_with(VecDeque::new);

        // Add to cyclic buffer
        logs.push_back(log.clone());
        if logs.len() > MAX_MESSAGES_PER_LAYER {
            logs.pop_front();
        }

        drop(inner);

        // Broadcast the message log update
        let update = StateUpdate::MessageLog {
            layer_id: log.layer_id,
            log,
        };
        let _ = self.update_tx.send(update);
    }

    /// Get message logs for a specific layer.
    pub async fn get_layer_logs(&self, layer_id: LayerId) -> Vec<MessageLog> {
        let inner = self.inner.read().await;
        inner.message_logs.get(&layer_id).map(|logs| logs.iter().cloned().collect()).unwrap_or_default()
    }

    /// Remove an intproxy from the state.
    #[allow(dead_code)]
    pub async fn remove_intproxy(&self, id: &IntproxyId) {
        debug!("Removing intproxy: {}", id);

        let mut inner = self.inner.write().await;
        inner.intproxies.remove(id);

        drop(inner);
        self.broadcast_update().await;
    }

    /// Clean up stale intproxies (no heartbeat for > 30s).
    pub async fn cleanup_stale(&self) {
        let now = SystemTime::now();
        let stale_cutoff = now - STALE_TIMEOUT;

        let mut inner = self.inner.write().await;
        let initial_count = inner.intproxies.len();

        inner.intproxies.retain(|id, info| {
            let heartbeat_time: SystemTime = info.last_heartbeat.into();
            let is_stale = heartbeat_time < stale_cutoff;

            if is_stale {
                debug!("Removing stale intproxy: {}", id);
            }

            !is_stale
        });

        let removed = initial_count - inner.intproxies.len();
        if removed > 0 {
            drop(inner);
            self.broadcast_update().await;
        }
    }

    /// Get a snapshot of the current state.
    pub async fn snapshot(&self) -> StateUpdate {
        let inner = self.inner.read().await;
        StateUpdate::Snapshot {
            intproxies: inner.intproxies.clone(),
        }
    }

    /// Subscribe to state updates.
    pub fn subscribe(&self) -> broadcast::Receiver<StateUpdate> {
        self.update_tx.subscribe()
    }

    /// Broadcast a state update to all WebSocket clients.
    async fn broadcast_update(&self) {
        let update = self.snapshot().await;

        // Ignore send errors (no receivers is fine)
        let _ = self.update_tx.send(update);
    }
}

impl Default for DebuggerState {
    fn default() -> Self {
        Self::new()
    }
}
