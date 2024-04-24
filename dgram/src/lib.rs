pub mod socket_setup;
pub mod sync;
mod syscalls;
#[cfg(feature = "async")]
pub mod tokio;

#[cfg(target_os = "linux")]
mod linux_imports {
    pub(super) use crate::syscalls::recv_msg;
    pub(super) use crate::syscalls::send_msg;
    pub(super) use nix::errno::Errno;
    pub(super) use nix::sys::socket::getsockopt;
    pub(super) use nix::sys::socket::recvmsg;
    pub(super) use nix::sys::socket::sendmsg;
    pub(super) use nix::sys::socket::setsockopt;
    pub(super) use nix::sys::socket::sockopt::ReceiveTimestampns;
    pub(super) use nix::sys::socket::sockopt::RxqOvfl;
    pub(super) use nix::sys::socket::sockopt::TxTime;
    pub(super) use nix::sys::socket::sockopt::UdpGroSegment;
    pub(super) use nix::sys::socket::sockopt::UdpGsoSegment;
    pub(super) use nix::sys::socket::AddressFamily;
    pub(super) use nix::sys::socket::ControlMessage;
    pub(super) use nix::sys::socket::MsgFlags;
    pub(super) use nix::sys::socket::SetSockOpt;
    pub(super) use nix::sys::socket::SockaddrLike;
    pub(super) use nix::sys::socket::SockaddrStorage;
    pub(super) use smallvec::SmallVec;
    pub(super) use std::io::IoSlice;
    pub(super) use std::io::IoSliceMut;
    pub(super) use std::net::SocketAddrV4;
    pub(super) use std::net::SocketAddrV6;
    pub(super) use std::os::fd::AsRawFd;

    #[cfg(feature = "async")]
    pub(super) use crate::async_imports::*;
}

#[cfg(feature = "async")]
mod async_imports {
    pub(super) use std::io::ErrorKind;
    pub(super) use tokio::io::Interest;
    pub(super) use tokio::net::UdpSocket;
}
