use crate::syscalls::RecvData;
use crate::GsoSettings;
use std::io::Result;
use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::time::Instant;

#[cfg(target_os = "linux")]
use super::linux_imports::*;

#[cfg(target_os = "linux")]
pub async fn send_to(
    socket: &UdpSocket, send_buf: &[u8], gso_settings: Option<GsoSettings>,
    tx_time: Option<Instant>, client_addr: &SocketAddr,
) -> Result<usize> {
    loop {
        // Important to use try_io so that Tokio can clear the socket's readiness
        // flag
        let res = socket.try_io(Interest::WRITABLE, || {
            let fd = socket.as_fd();
            send_msg(
                fd,
                send_buf,
                gso_settings,
                tx_time,
                &SockaddrStorage::from(*client_addr),
            )
            .map_err(Into::into)
        });

        match res {
            Err(e) if e.kind() == ErrorKind::WouldBlock =>
                socket.writable().await?,
            res => return res,
        }
    }
}

#[cfg(target_os = "linux")]
pub async fn recv_from(
    socket: &UdpSocket, read_buf: &mut [u8], cmsg_space: &mut Vec<u8>,
    msg_flags: Option<MsgFlags>,
) -> Result<RecvData> {
    loop {
        // Important to use try_io so that Tokio can clear the socket's readiness
        // flag
        let res = socket.try_io(Interest::READABLE, || {
            let fd = socket.as_fd();
            recv_msg(
                fd,
                read_buf,
                cmsg_space,
                msg_flags.unwrap_or(MsgFlags::empty()),
            )
            .map_err(Into::into)
        });

        match res {
            Err(e) if e.kind() == ErrorKind::WouldBlock =>
                socket.readable().await?,
            _ => return res,
        }
    }
}

#[cfg(not(target_os = "linux"))]
pub async fn send_to(
    socket: &UdpSocket, client_addr: SocketAddr, send_buf: &[u8],
    _segment_size: usize, _num_pkts: usize, _tx_time: Option<Instant>,
) -> Result<usize> {
    socket.send_to(send_buf, client_addr).await
}

// Signature changes because we can't use MessageFlags outside of a *NIX context
#[cfg(not(target_os = "linux"))]
pub async fn recv_from(
    socket: &UdpSocket, read_buf: &mut [u8], _cmsg_space: &mut Vec<u8>,
) -> Result<RecvData> {
    let recv = socket.recv(read_buf).await?;

    Ok(RecvData {
        bytes: recv,
        peer_addr: None,
        metrics: None,
        gro: None,
        rx_time: None,
    })
}
