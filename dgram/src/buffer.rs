use std::fs::metadata;
use std::io::IoSlice;
use std::io::IoSliceMut;
use std::io::Result;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::os::fd::AsRawFd;
use std::time::Instant;
use std::time::SystemTime;

// TODO: test multi-platform bits, ensure linux/non-linux pieces are separate

#[cfg(all(target_os = "linux", not(fuzzing)))]
mod linux_imports {
    pub(super) use nix::sys::socket::sendmsg;
    pub(super) use nix::sys::socket::ControlMessage;
    pub(super) use nix::sys::socket::MsgFlags;
    pub(super) use nix::sys::socket::SockaddrLike;
    pub(super) use smallvec::SmallVec;
}

use nix::errno::Errno;
use nix::sys::socket::recvmsg;
use nix::sys::socket::AddressFamily;
use nix::sys::socket::ControlMessageOwned;
use nix::sys::socket::SockaddrStorage;

#[cfg(all(target_os = "linux", not(fuzzing)))]
use self::linux_imports::*;

#[cfg(any(not(target_os = "linux"), fuzzing))]
mod non_linux_imports {
    pub(super) use std::net::SocketAddr;
}

const UDP_MAX_GSO_PACKET_SIZE: usize = 65507;

#[cfg(any(not(target_os = "linux"), fuzzing))]
use self::non_linux_imports::*;

#[cfg(any(not(target_os = "linux"), fuzzing))]
pub fn send_to(
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
pub fn send_to<S>(
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

    let iov = [IoSlice::new(send_buf)];
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

    sendmsg(fd.as_raw_fd(), &iov, &cmsgs, MsgFlags::empty(), client_addr)
        .map_err(Into::into)
}

/// Output of a `recvmsg` call
pub struct RecvData {
    pub bytes: usize,
    pub peer_addr: Option<SocketAddr>,
    pub rx_time: Option<SystemTime>,
    pub gro: Option<u16>,
}

/// Receive a message via `recvmsg`.
///
/// # Note
///
/// It is the caller's responsibility to create and clear the cmsg space. `nix`
/// recommends that the space be created via the `cmsg_space!()` macro.
pub fn recv_from(
    fd: impl AsRawFd, read_buf: &mut [u8], cmsg_space: &mut Vec<u8>,
    msg_flags: Option<MsgFlags>,
) -> std::result::Result<RecvData, Errno> {
    cmsg_space.clear();

    let iov_s = &mut [IoSliceMut::new(read_buf)];
    let msg_flags = msg_flags.unwrap_or(MsgFlags::empty());

    match recvmsg::<SockaddrStorage>(
        fd.as_raw_fd(),
        iov_s,
        Some(cmsg_space),
        msg_flags,
    ) {
        Ok(r) => {
            println!("{:?}", r);
            let bytes = r.bytes;

            let address = match r.address {
                Some(a) => a,
                _ => return Err(Errno::EINVAL.into()),
            };

            let peer_addr = match address.family() {
                Some(AddressFamily::Inet) => Some(
                    SocketAddrV4::from(*address.as_sockaddr_in().unwrap()).into(),
                ),
                Some(AddressFamily::Inet6) => Some(
                    SocketAddrV6::from(*address.as_sockaddr_in6().unwrap())
                        .into(),
                ),
                _ => None,
            };

            let mut rx_time = None;
            let mut gro = None;

            for cmsg in r.cmsgs() {
                match cmsg {
                    ControlMessageOwned::RxqOvfl(c) =>
                        println!("TODO: udp packet drop count metrics? // {c}"),
                    ControlMessageOwned::ScmTimestampns(val) => {
                        rx_time = SystemTime::UNIX_EPOCH.checked_add(val.into());
                    },
                    ControlMessageOwned::UdpGroSegments(val) => {
                        println!("val: {:?}", val);
                        gro = Some(val);
                    },
                    _ => return Err(Errno::EINVAL.into()),
                }
            }

            Ok(RecvData {
                peer_addr,
                bytes,
                gro,
                rx_time,
            })
        },
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use nix::cmsg_space;
    use nix::sys::socket::sockopt::UdpGroSegment;
    use nix::sys::socket::sockopt::UdpGsoSegment;
    use nix::sys::socket::*;
    use nix::sys::time::TimeVal;
    use std::io::IoSliceMut;
    use std::io::Result;
    use std::str::FromStr;

    use super::*;

    fn new_sockets() -> Result<(i32, i32)> {
        let recv = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            SockProtocol::Udp,
        )
        .unwrap();
        setsockopt(recv, UdpGroSegment, &true)?;
        let localhost = SockaddrIn::from_str("127.0.0.1:0").unwrap();
        bind(recv, &localhost).unwrap();

        let send = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            SockProtocol::Udp,
        )
        .unwrap();
        setsockopt(send, UdpGsoSegment, &1).unwrap();

        Ok((send, recv))
    }

    #[test]
    fn send_to_simple() -> Result<()> {
        let (send, recv) = new_sockets()?;
        let addr = getsockname::<SockaddrStorage>(recv).unwrap();

        let send_buf = b"njd";
        send_to(
            send,
            send_buf,
            UDP_MAX_GSO_PACKET_SIZE,
            1,
            None,
            Some(&addr),
        )?;

        let mut buf = [0; 3];
        let mut read_buf = [IoSliceMut::new(&mut buf)];
        let recv =
            recvmsg::<()>(recv, &mut read_buf, None, MsgFlags::empty()).unwrap();

        assert_eq!(recv.bytes, 3);
        assert_eq!(
            String::from_utf8(buf.to_vec()).unwrap().as_bytes(),
            send_buf
        );

        Ok(())
    }

    #[test]
    fn send_to_invalid_tx_time() -> Result<()> {
        let (send, recv) = new_sockets()?;
        let addr = getsockname::<SockaddrStorage>(recv).unwrap();

        let send_buf = b"nyj";
        send_to(
            send,
            send_buf,
            UDP_MAX_GSO_PACKET_SIZE,
            1,
            // Invalid because we pass this Instant by the time we call sendmsg()
            Some(Instant::now()),
            Some(&addr),
        )?;

        let mut buf = [0; 3];
        let mut read_buf = [IoSliceMut::new(&mut buf)];
        let recv =
            recvmsg::<()>(recv, &mut read_buf, None, MsgFlags::empty()).unwrap();

        assert_eq!(recv.bytes, 3);
        assert_eq!(
            String::from_utf8(buf.to_vec()).unwrap().as_bytes(),
            send_buf
        );

        Ok(())
    }

    #[test]
    fn send_to_multiple_segments() -> Result<()> {
        let (send, recv) = new_sockets()?;
        let addr = getsockname::<SockaddrStorage>(recv).unwrap();

        let send_buf = b"devils";
        send_to(send, send_buf, 1, 6, None, Some(&addr))?;

        let mut buf = [0; 6];
        let mut read_buf = [IoSliceMut::new(&mut buf)];
        let mut x = cmsg_space!(u32);
        let recv =
            recvmsg::<()>(recv, &mut read_buf, Some(&mut x), MsgFlags::empty())
                .unwrap();
        println!("{:?}", recv);

        assert_eq!(recv.bytes, 6);
        assert_eq!(
            String::from_utf8(buf.to_vec()).unwrap().as_bytes(),
            send_buf
        );

        Ok(())
    }

    #[test]
    fn send_to_control_messages() -> Result<()> {
        let (send, recv) = new_sockets()?;

        let send_buf = b"nyj";
        send_to(
            send,
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
            recvmsg::<()>(recv, &mut read_buf, None, MsgFlags::empty()).unwrap();

        assert_eq!(recv.bytes, 3);
        assert_eq!(
            String::from_utf8(buf.to_vec()).unwrap().as_bytes(),
            send_buf
        );

        Ok(())
    }

    #[test]
    fn recv_from_simple() -> Result<()> {
        let (send, recv) = new_sockets()?;

        // TODO: how to handle cmsgs
        let send_buf = b"jets";
        let iov = [IoSlice::new(send_buf)];
        sendmsg::<()>(send, &iov, &[], MsgFlags::empty(), None)?;

        let mut cmsg_space = cmsg_space!(TimeVal);
        let mut read_buf = [0; 4];

        let recv_data = recv_from(recv, &mut read_buf, &mut cmsg_space, None)?;

        assert_eq!(recv_data.bytes, 4);
        assert_eq!(&read_buf, b"jets");

        Ok(())
    }

    #[test]
    fn recv_from_control_message() -> Result<()> {
        let (send, recv) = new_sockets()?;
        let addr = getsockname::<SockaddrStorage>(recv).unwrap();

        // TODO: how to handle cmsgs
        let send_buf = b"jets";
        let iov = [IoSlice::new(send_buf)];
        let send_cmsgs = vec![ControlMessage::UdpGsoSegments(&2)];
        sendmsg(send, &iov, &send_cmsgs, MsgFlags::empty(), Some(&addr))?;

        let mut cmsg_space = cmsg_space!(u32);
        let mut read_buf = [0; 4];

        let recv_data = recv_from(recv, &mut read_buf, &mut cmsg_space, None)?;

        // println!("read buf: {:?}", read_buf);
        // println!("cmsg space: {:?}", cmsg_space);
        // println!("gro {:?}", getsockopt(recv, UdpGroSegment));

        assert_eq!(recv_data.bytes, 4);
        assert_eq!(&read_buf, b"jets");

        assert_eq!(recv_data.gro, Some(1));

        Ok(())
    }
}
