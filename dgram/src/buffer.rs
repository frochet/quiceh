use std::io::Result;
use std::os::fd::AsRawFd;
use std::time::Instant;

#[cfg(all(target_os = "linux", not(fuzzing)))]
mod linux_imports {
    pub(super) use nix::sys::socket::sendmsg;
    pub(super) use nix::sys::socket::ControlMessage;
    pub(super) use nix::sys::socket::MsgFlags;
    pub(super) use nix::sys::socket::SockaddrLike;
    pub(super) use smallvec::SmallVec;
}

#[cfg(all(target_os = "linux", not(fuzzing)))]
use self::linux_imports::*;

#[cfg(any(not(target_os = "linux"), fuzzing))]
mod non_linux_imports {
    pub(super) use std::net::SocketAddr;
}

#[cfg(any(not(target_os = "linux"), fuzzing))]
use self::non_linux_imports::*;

// An instant with the value of zero, since [`Instant`] is backed by a version
// of timespec this allows to extract raw values from an [`Instant`]
const INSTANT_ZERO: Instant = unsafe { std::mem::transmute(0u128) };

#[cfg(any(not(target_os = "linux"), fuzzing))]
fn send_to(
    fd: impl AsRawFd, send_buf: &[u8], segment_size: usize, num_pkts: usize,
    tx_time: Option<Instant>, client_addr: Option<SocketAddr>,
) -> Result<usize> {
    sendmsg(
        fd.as_raw_fd(),
        &iov,
        &cmsgs,
        MsgFlags::empty(),
        addr.as_ref(),
    )
    .map_err(Into::into)
}

#[cfg(all(target_os = "linux", not(fuzzing)))]
fn send_to<S>(
    fd: impl AsRawFd, send_buf: &[u8], segment_size: usize, num_pkts: usize,
    tx_time: Option<Instant>, client_addr: Option<&S>,
) -> Result<usize>
where
    S: SockaddrLike,
{
    loop {
        let iov = [std::io::IoSlice::new(send_buf)];
        let segment_size_u16 = segment_size as u16;

        let raw_time = tx_time
            .map(|t| t.duration_since(INSTANT_ZERO).as_nanos() as u64)
            .unwrap_or(0);

        let mut cmsgs: SmallVec<[ControlMessage; 2]> = SmallVec::new();

        if num_pkts > 1 {
            // Create cmsg for UDP_SEGMENT.
            cmsgs.push(ControlMessage::UdpGsoSegments(&segment_size_u16));
        }

        if tx_time.is_some() {
            // Create cmsg for TXTIME.
            cmsgs.push(ControlMessage::TxTime(&raw_time));
        }

        return sendmsg(
            fd.as_raw_fd(),
            &iov,
            &cmsgs,
            MsgFlags::empty(),
            client_addr,
        )
        .map_err(Into::into);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send() {
        use nix::sys::socket::*;
        use nix::unistd::pipe;
        use std::io::IoSlice;
        use std::str::FromStr;
        let localhost = SockaddrIn::from_str("1.2.3.4:8080").unwrap();
        let fd = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            None,
        )
        .unwrap();
        let (r, w) = pipe().unwrap();

        let iov = [IoSlice::new(b"hello")];
        let fds = [r];
        let cmsg = ControlMessage::ScmRights(&fds);
        let segment_size = 65557;
        let num_pkts = 1;

        super::send_to(r, &iov, segment_size, num_pkts, None, None);
    }

    fn test_recv() {}
}
