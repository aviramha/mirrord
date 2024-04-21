use std::{fmt, net::Ipv4Addr, thread};

use mirrord_protocol::vpn::{ClientVpn, NetworkConfiguration, ServerVpn};
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use tokio::{
    io::unix::AsyncFd,
    net::UdpSocket,
    select,
    sync::mpsc::{self, error::SendError, Receiver, Sender},
};

use crate::{
    error::Result,
    util::run_thread_in_namespace,
    watched_task::{TaskStatus, WatchedTask},
};

/// An interface for a background task handling [`LayerTcpOutgoing`] messages.
/// Each agent client has their own independent instance (neither this wrapper nor the background
/// task are shared).
pub(crate) struct VpnApi {
    /// Holds the thread in which [`TcpOutgoingTask`] is running.
    _task: thread::JoinHandle<()>,

    /// Status of the [`TcpOutgoingTask`].
    task_status: TaskStatus,

    /// Sends the layer messages to the [`TcpOutgoingTask`].
    layer_tx: Sender<ClientVpn>,

    /// Reads the daemon messages from the [`TcpOutgoingTask`].
    daemon_rx: Receiver<ServerVpn>,
}

impl VpnApi {
    const TASK_NAME: &'static str = "Vpn";

    /// Spawns a new background task for handling `outgoing` feature and creates a new instance of
    /// this struct to serve as an interface.
    ///
    /// # Params
    ///
    /// * `pid` - process id of the agent's target container
    #[tracing::instrument(level = "trace")]
    pub(crate) fn new(pid: Option<u64>) -> Self {
        let (layer_tx, layer_rx) = mpsc::channel(1000);
        let (daemon_tx, daemon_rx) = mpsc::channel(1000);

        let watched_task = WatchedTask::new(
            Self::TASK_NAME,
            VpnTask::new(pid, layer_rx, daemon_tx).run(),
        );
        let task_status = watched_task.status();
        let task = run_thread_in_namespace(
            watched_task.start(),
            Self::TASK_NAME.to_string(),
            pid,
            "net",
        );

        Self {
            _task: task,
            task_status,
            layer_tx,
            daemon_rx,
        }
    }

    /// Sends the [`LayerTcpOutgoing`] message to the background task.
    #[tracing::instrument(level = "trace", skip(self))]
    pub(crate) async fn layer_message(&mut self, message: ClientVpn) -> Result<()> {
        if self.layer_tx.send(message).await.is_ok() {
            Ok(())
        } else {
            Err(self.task_status.unwrap_err().await)
        }
    }

    /// Receives a [`DaemonTcpOutgoing`] message from the background task.
    pub(crate) async fn daemon_message(&mut self) -> Result<ServerVpn> {
        match self.daemon_rx.recv().await {
            Some(msg) => Ok(msg),
            None => Err(self.task_status.unwrap_err().await),
        }
    }
}

pub struct AsyncRawSocket {
    inner: AsyncFd<Socket>,
    addr: SockAddr,
}

impl AsyncRawSocket {
    pub fn new(socket: Socket, addr: SockAddr) -> std::io::Result<Self> {
        socket.set_nonblocking(true)?;
        Ok(Self {
            inner: AsyncFd::new(socket)?,
            addr,
        })
    }

    pub async fn readable(&self) -> std::io::Result<()> {
        self.inner.readable().await?;
        Ok(())
    }

    pub async fn read(&self, out: &mut [u8]) -> std::io::Result<usize> {
        loop {
            let mut guard = self.inner.readable().await?;

            match guard.try_io(|inner| inner.get_ref().recv(out)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }

    pub async fn write(&self, buf: &[u8]) -> std::io::Result<usize> {
        loop {
            let mut guard = self.inner.writable().await?;
            match guard.try_io(|inner| inner.get_ref().send_to(buf, self.addr)) {
                Ok(result) => return result,
                Err(_would_block) => continue,
            }
        }
    }
}

async fn create_raw_socket() -> Result<AsyncRawSocket> {
    let index = nix::net::if_::if_nametoindex("eth0").unwrap();

    let socket = Socket::new(
        Domain::PACKET,
        Type::DGRAM,
        Some(Protocol::from(libc::ETH_P_IP.to_be())),
    )?;
    let sock_addr = interface_index_to_sock_addr(index.try_into().unwrap());
    socket.bind(&sock_addr)?;
    socket.set_nonblocking(true)?;
    Ok(AsyncRawSocket::new(socket, sock_addr).unwrap())
}
use std::net::{IpAddr, SocketAddr};

use nix::sys::socket::SockaddrStorage;
#[tracing::instrument(level = "debug", ret)]
async fn resolve_interface() -> Result<(IpAddr, IpAddr, IpAddr)> {
    // Connect to a remote address so we can later get the default network interface.
    let temporary_socket = UdpSocket::bind("0.0.0.0:0").await?;
    temporary_socket.connect("8.8.8.8:53").await?;

    // Create comparison address here with `port: 0`, to match the network interface's address of
    // `sin_port: 0`.
    let local_address = SocketAddr::new(temporary_socket.local_addr()?.ip(), 0);
    let raw_local_address = SockaddrStorage::from(local_address);

    // Try to find an interface that matches the local ip we have.
    let usable_interface = nix::ifaddrs::getifaddrs()?
        .find(|iface| {
            (iface
                .address
                .map(|addr| addr == raw_local_address)
                .unwrap_or(false))
        })
        .unwrap();

    let ip = usable_interface
        .address
        .unwrap()
        .as_sockaddr_in()
        .unwrap()
        .ip()
        .to_be_bytes()
        .into();
    let net_mask = usable_interface
        .netmask
        .unwrap()
        .as_sockaddr_in()
        .unwrap()
        .ip()
        .to_be_bytes()
        .into();
    // extracting gateway is more difficult, ugly patch for now.
    let temp_gateway = usable_interface
        .address
        .unwrap()
        .as_sockaddr_in()
        .unwrap()
        .ip()
        .to_be_bytes();

    let gateway = IpAddr::V4(Ipv4Addr::new(
        temp_gateway[0],
        temp_gateway[1],
        temp_gateway[2],
        1,
    ))
    .into();

    Ok((ip, net_mask, gateway))
}

/// Handles outgoing connections for one client (layer).
struct VpnTask {
    pid: Option<u64>,
    layer_rx: Receiver<ClientVpn>,
    daemon_tx: Sender<ServerVpn>,
}

impl fmt::Debug for VpnTask {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VpnTask").field("pid", &self.pid).finish()
    }
}

fn interface_index_to_sock_addr(index: i32) -> SockAddr {
    let mut addr_storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
    unsafe {
        let sock_addr = std::ptr::addr_of_mut!(addr_storage) as *mut libc::sockaddr_ll;
        (*sock_addr).sll_family = libc::AF_PACKET as u16;
        (*sock_addr).sll_protocol = (libc::ETH_P_IP as u16).to_be();
        (*sock_addr).sll_ifindex = index;
    }

    unsafe { SockAddr::new(addr_storage, len) }
}

impl VpnTask {
    fn new(pid: Option<u64>, layer_rx: Receiver<ClientVpn>, daemon_tx: Sender<ServerVpn>) -> Self {
        Self {
            pid,
            layer_rx,
            daemon_tx,
        }
    }

    /// Runs this task as long as the channels connecting it with [`TcpOutgoingApi`] are open.
    async fn run(mut self) -> Result<()> {
        let mut raw_socket = create_raw_socket().await.unwrap();
        let mut buffer = [0u8; 1500 * 5];
        loop {
            select! {
                biased;

                message = self.layer_rx.recv() => match message {
                    // We have a message from the layer to be handled.
                    Some(message) => self.handle_layer_msg(message, &mut raw_socket).await.unwrap(),
                    // Our channel with the layer is closed, this task is no longer needed.
                    None => {
                        tracing::trace!("VpnTask -> Channel with the layer is closed, exiting.");
                        break Ok(());
                    },
                },

                // We have data coming from one of our peers.
                ready = raw_socket.readable() => {
                    if let Ok(()) = ready {
                        let len = raw_socket.read(&mut buffer).await?;
                        let packet = buffer[..len].to_vec();
                        self.daemon_tx.send(ServerVpn::Packet(packet)).await.unwrap();
                    }
                },
            }
        }
    }

    #[tracing::instrument(level = "trace", skip(socket), ret, err(Debug))]
    async fn handle_layer_msg(
        &mut self,
        message: ClientVpn,
        socket: &mut AsyncRawSocket,
    ) -> Result<(), SendError<ServerVpn>> {
        match message {
            // We make connection to the requested address, split the stream into halves with
            // `io::split`, and put them into respective maps.
            ClientVpn::GetNetworkConfiguration => {
                // Try to find an interface that matches the local ip we have.
                let (ip, net_mask, gateway) = resolve_interface().await.unwrap();
                self.daemon_tx
                    .send(
                        (ServerVpn::NetworkConfiguration(NetworkConfiguration {
                            ip,
                            net_mask,
                            gateway,
                        })),
                    )
                    .await
                    .unwrap();
            }
            ClientVpn::Packet(packet) => {
                socket.write(&packet).await.unwrap();
            }
        }

        Ok(())
    }
}
