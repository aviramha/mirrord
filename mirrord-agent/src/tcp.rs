use mirrord_protocol::{ConnectionID, Port, tcp::{LayerTcp, DaemonTcp}};

use crate::{common::PeerID, util::Subscriptions};

#[derive(Debug, Default)]
pub struct TcpSnifferHandler {
    port_subscriptions: Subscriptions<Port, PeerID>,
    connections_subscriptions: Subscriptions<ConnectionID, PeerID>,
}

pub struct TcpSnifferIn {
    message: LayerTcp,
    peer: PeerID
}

pub struct TcpSnifferOut {
    message: DaemonTcp,
    peer: PeerID
}

pub struct TcpSnifferApi {}