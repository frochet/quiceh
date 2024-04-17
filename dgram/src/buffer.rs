use std::io::Result;
use std::os::fd::AsRawFd;
use std::time::Instant;

// TODO: test multi-platform bits

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

pub const UDP_MAX_GSO_PACKET_SIZE: usize = 65507;

#[cfg(any(not(target_os = "linux"), fuzzing))]
use self::non_linux_imports::*;

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
    // An instant with the value of zero, since [`Instant`] is backed by a version
    // of timespec this allows to extract raw values from an [`Instant`]
    const INSTANT_ZERO: Instant = unsafe { std::mem::transmute(0u128) };

    let now = Instant::now();

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

    if tx_time.filter(|t| t > &now).is_some() {
        // Create cmsg for TXTIME.
        cmsgs.push(ControlMessage::TxTime(&raw_time));
    }

    return sendmsg(fd.as_raw_fd(), &iov, &cmsgs, MsgFlags::empty(), client_addr)
        .map_err(Into::into);
}

#[cfg(test)]
mod tests {
    use nix::sys::socket::*;
    use std::io::IoSliceMut;
    use std::io::Result;

    use super::*;

    fn create_sockets() -> (i32, i32) {
        socketpair(
            AddressFamily::Unix,
            SockType::Stream,
            None,
            SockFlag::empty(),
        )
        .unwrap()
    }

    #[test]
    fn test_send_to_simple() -> Result<()> {
        let (fd1, fd2) = create_sockets();

        let send_buf = b"njd";
        send_to(
            fd1,
            send_buf,
            UDP_MAX_GSO_PACKET_SIZE,
            1,
            None,
            None::<&SockaddrStorage>,
        )?;

        let mut buf = [0; 3];
        let mut read_buf = [IoSliceMut::new(&mut buf)];
        let recv =
            recvmsg::<()>(fd2, &mut read_buf, None, MsgFlags::empty()).unwrap();

        assert_eq!(recv.bytes, 3);
        assert_eq!(
            String::from_utf8(buf.to_vec()).unwrap().as_bytes(),
            send_buf
        );

        Ok(())
    }

    #[test]
    fn test_send_to_invalid_tx_time() -> Result<()> {
        let (fd1, fd2) = create_sockets();

        let send_buf = b"nyj";
        send_to(
            fd1,
            send_buf,
            UDP_MAX_GSO_PACKET_SIZE,
            1,
            // Invalid because we pass this Instant by the time we call sendmsg()
            Some(Instant::now()),
            None::<&SockaddrStorage>,
        )?;

        let mut buf = [0; 3];
        let mut read_buf = [IoSliceMut::new(&mut buf)];
        let recv =
            recvmsg::<()>(fd2, &mut read_buf, None, MsgFlags::empty()).unwrap();

        assert_eq!(recv.bytes, 3);
        assert_eq!(
            String::from_utf8(buf.to_vec()).unwrap().as_bytes(),
            send_buf
        );

        Ok(())
    }

    #[test]
    fn test_send_to_multiple_packets() -> Result<()> {
        let (fd1, fd2) = create_sockets();

        let send_buf = b"devils";
        send_to(
            fd1,
            send_buf,
            1,
            6,
            Some(Instant::now()),
            None::<&SockaddrStorage>,
        )?;

        let mut buf = [0; 6];
        let mut read_buf = [IoSliceMut::new(&mut buf)];
        let recv =
            recvmsg::<()>(fd2, &mut read_buf, None, MsgFlags::empty()).unwrap();

        assert_eq!(recv.bytes, 6);
        assert_eq!(
            String::from_utf8(buf.to_vec()).unwrap(),
            "devils".to_owned()
        );
        assert_eq!(
            String::from_utf8(buf.to_vec()).unwrap().as_bytes(),
            send_buf
        );

        Ok(())
    }

    fn test_recv() {}
}
