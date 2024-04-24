use std::io;
use std::os::fd::AsRawFd;
use std::os::fd::RawFd;

/// Indicators of settings applied to a socket. These settings aren't "applied"
/// to a socket. Rather, the same (maximal) settings are always applied to a
/// socket, and this struct indicates which of those settings were successfully
/// applied to a socket.
#[derive(Default)]
pub struct SocketCapabilities {
    /// Indicates if the socket has "Generic Segmentation Offload" enabled.
    pub has_gso: bool,

    /// Indicates if the socket has "SO_RXQ_OVFL" set.
    pub check_udp_drop: bool,

    /// Indicates if the monotonic clock is set for transimssion timestamps.
    pub has_txtime: bool,

    /// Indicates if the monotonic clock is set for receiving timestamps.
    pub has_rxtime: bool,

    /// Indicates if the socket has "Generic Receive Offload" enabled.
    pub has_gro: bool,
}

impl SocketCapabilities {
    /// Try applying maximal settings to a socket and returns indicators of
    /// which settings were successfully applied.
    #[cfg(unix)]
    pub fn apply_all_and_get_compatibility<S>(
        socket: &S, max_send_udp_payload_size: usize,
    ) -> Self
    where
        S: AsRawFd,
    {
        let raw_fd = socket.as_raw_fd();

        Self {
            has_gso: set_udp_segment(raw_fd, max_send_udp_payload_size).is_ok(),
            check_udp_drop: set_udp_rxq_ovfl(socket).is_ok(),
            has_txtime: set_tx_time(raw_fd).is_ok(),
            has_rxtime: set_rx_time(raw_fd).is_ok(),
            has_gro: set_gro(raw_fd).is_ok(),
        }
    }
}

#[cfg(target_os = "linux")]
pub fn set_udp_segment(sock: RawFd, segment: usize) -> io::Result<()> {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::UdpGsoSegment;

    setsockopt(sock, UdpGsoSegment, &(segment as i32))?;

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn set_gro(sock: RawFd) -> io::Result<()> {
    use nix::sys::socket::sockopt::UdpGroSegment;
    use nix::sys::socket::SetSockOpt;

    UdpGroSegment.set(sock, &true)?;

    Ok(())
}

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
pub fn set_gro(_: RawFd) -> io::Result<()> {
    Err("unsupported").into_io()
}

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
pub fn set_udp_segment(_: RawFd, _: usize) -> io::Result<()> {
    Err("unsupported").into_io()
}

#[cfg(target_os = "linux")]
fn set_udp_rxq_ovfl<S>(sock: &S) -> io::Result<()>
where
    S: AsRawFd,
{
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::RxqOvfl;

    setsockopt(sock.as_raw_fd(), RxqOvfl, &1)?;

    Ok(())
}

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
fn set_udp_rxq_ovfl<S>(_: &S) -> io::Result<()>
where
    S: AsRawFd,
{
    Err("unsupported").into_io()
}

#[cfg(target_os = "linux")]
pub fn set_tx_time(sock: RawFd) -> io::Result<()> {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::TxTime;

    let cfg = libc::sock_txtime {
        clockid: libc::CLOCK_MONOTONIC,
        flags: 0,
    };

    setsockopt(sock, TxTime, &cfg)?;

    Ok(())
}

#[cfg(any(target_os = "android", target_os = "ios", target_os = "macos"))]
pub fn set_tx_time(_: RawFd) -> io::Result<()> {
    Err("unsupported").into_io()
}

#[cfg(target_os = "linux")]
pub fn set_rx_time(sock: RawFd) -> io::Result<()> {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::ReceiveTimestampns;

    setsockopt(sock, ReceiveTimestampns, &true)?;

    Ok(())
}

#[cfg(target_os = "macos")]
pub fn set_rx_time(_: RawFd) -> io::Result<()> {
    Err("unsupported").into_io()
}
