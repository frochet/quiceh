use crate::syscalls::RecvData;
use crate::GsoSettings;
use mio::net::UdpSocket;
use std::io::Result;
use std::net::SocketAddr;
use std::time::Instant;

#[cfg(target_os = "linux")]
use super::linux_imports::*;

#[cfg(target_os = "linux")]
pub fn send_to(
    socket: &UdpSocket, send_buf: &[u8], gso_settings: Option<GsoSettings>,
    tx_time: Option<Instant>, client_addr: &SocketAddr,
) -> Result<usize> {
    loop {
        // Important to use try_io so events keep coming even if we see
        // EAGAIN/EWOULDBLOCK
        let res = socket.try_io(|| {
            // mio::net::UdpSocket doesn't implement AsFd (yet?).
            let fd = unsafe {
                std::os::fd::BorrowedFd::borrow_raw(socket.as_raw_fd())
            };

            let sent = send_msg(
                fd,
                send_buf,
                gso_settings,
                tx_time,
                &SockaddrStorage::from(*client_addr),
            );

            match sent {
                Err(Errno::EAGAIN) => Err(std::io::Error::last_os_error()),
                _ => Ok(sent),
            }
        });

        if let Ok(sent) = res {
            return sent.map_err(Into::into);
        }
    }
}

#[cfg(target_os = "linux")]
pub async fn recv_from(
    socket: &UdpSocket, read_buf: &mut [u8], cmsg_space: &mut Vec<u8>,
    msg_flags: Option<MsgFlags>,
) -> Result<RecvData> {
    loop {
        // Important to use try_io so events keep coming even if we see
        // EAGAIN/EWOULDBLOCK
        let res = socket.try_io(|| {
            // mio::net::UdpSocket doesn't implement AsFd (yet?).
            let fd = unsafe {
                std::os::fd::BorrowedFd::borrow_raw(socket.as_raw_fd())
            };

            let recvd = recv_msg(
                fd,
                read_buf,
                cmsg_space,
                msg_flags.unwrap_or(MsgFlags::empty()),
            );

            match recvd {
                Err(Errno::EAGAIN) => Err(std::io::Error::last_os_error()),
                _ => Ok(recvd),
            }
        });

        if let Ok(recvd) = res {
            return recvd.map_err(Into::into);
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
