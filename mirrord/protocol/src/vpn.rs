use std::{
    net::IpAddr
};

use bincode::{Decode, Encode};


#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub struct NetworkConfiguration {
    pub ip: IpAddr,
    pub net_mask: IpAddr,
    pub gateway: IpAddr,
}

#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub enum ClientVpn {
    GetNetworkConfiguration,
    Packet(Vec<u8>)
}

/// Messages related to Tcp handler from server.
#[derive(Encode, Decode, Debug, PartialEq, Eq, Clone)]
pub enum ServerVpn {
    NetworkConfiguration(NetworkConfiguration),
    Packet(Vec<u8>)
}
