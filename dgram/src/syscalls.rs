use std::io::IoSlice;
use std::io::IoSliceMut;
use std::io::Result;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::os::fd::AsRawFd;
use std::time::Instant;
use std::time::SystemTime;

#[cfg(target_os = "linux")]
mod linux_imports {
    pub(super) use nix::errno::Errno;
    pub(super) use nix::sys::socket::recvmsg;
    pub(super) use nix::sys::socket::sendmsg;
    pub(super) use nix::sys::socket::AddressFamily;
    pub(super) use nix::sys::socket::ControlMessage;
    pub(super) use nix::sys::socket::ControlMessageOwned;
    pub(super) use nix::sys::socket::MsgFlags;
    pub(super) use nix::sys::socket::SockaddrLike;
    pub(super) use nix::sys::socket::SockaddrStorage;
    pub(super) use smallvec::SmallVec;
}

#[cfg(target_os = "linux")]
use self::linux_imports::*;

// An instant with the value of zero, since [`Instant`] is backed by a version
// of timespec this allows to extract raw values from an [`Instant`]
const INSTANT_ZERO: Instant = unsafe { std::mem::transmute(0u128) };

#[cfg(target_os = "linux")]
pub fn send_msg(
    fd: impl AsRawFd, send_buf: &[u8], segment_size: usize, num_pkts: usize,
    tx_time: Option<Instant>, client_addr: &SockaddrStorage,
) -> Result<usize> {
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

    sendmsg(
        fd.as_raw_fd(),
        &iov,
        &cmsgs,
        MsgFlags::empty(),
        Some(client_addr),
    )
    .map_err(Into::into)
}

/// Output of a `recvmsg` call
pub struct RecvData {
    pub bytes: usize,
    pub peer_addr: Option<SocketAddr>,
    pub cmsgs: Vec<ControlMessageOwned>,
    pub gro: Option<u16>,
    pub rx_time: Option<SystemTime>,
}

impl RecvData {
    pub fn new(
        peer_addr: Option<SocketAddr>, bytes: usize, cmsg_space: usize,
    ) -> Self {
        Self {
            peer_addr,
            bytes,
            cmsgs: Vec::with_capacity(cmsg_space),
            gro: None,
            rx_time: None,
        }
    }
}

/// Receive a message via `recvmsg`.
///
/// # Note
///
/// It is the caller's responsibility to create and clear the cmsg space. `nix`
/// recommends that the space be created via the `cmsg_space!()` macro.
pub fn recv_msg(
    fd: impl AsRawFd, read_buf: &mut [u8], cmsg_space: &mut Vec<u8>,
    msg_flags: Option<MsgFlags>,
) -> std::result::Result<RecvData, Errno> {
    cmsg_space.clear();

    let iov_s = &mut [IoSliceMut::new(read_buf)];
    let msg_flags = msg_flags.unwrap_or(MsgFlags::empty());
    let cmsg_cap = cmsg_space.capacity();

    match recvmsg::<SockaddrStorage>(
        fd.as_raw_fd(),
        iov_s,
        Some(cmsg_space),
        msg_flags,
    ) {
        Ok(r) => {
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

            let mut recv_data = RecvData::new(peer_addr, bytes, cmsg_cap);

            r.cmsgs().for_each(|msg| match msg {
                ControlMessageOwned::ScmTimestampns(time) =>
                    recv_data.rx_time =
                        SystemTime::UNIX_EPOCH.checked_add(time.into()),
                ControlMessageOwned::UdpGroSegments(gro) =>
                    recv_data.gro = Some(gro),
                _ => recv_data.cmsgs.push(msg),
            });

            Ok(recv_data)
        },
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use nix::cmsg_space;
    use nix::sys::socket::sockopt::ReceiveTimestampns;
    use nix::sys::socket::sockopt::UdpGroSegment;
    use nix::sys::socket::*;
    use nix::sys::time::TimeVal;
    use std::io::IoSliceMut;
    use std::io::Result;
    use std::str::FromStr;

    use super::*;

    const UDP_MAX_GSO_PACKET_SIZE: usize = 65507;

    fn new_sockets() -> Result<(i32, i32)> {
        let recv = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            SockProtocol::Udp,
        )
        .unwrap();
        setsockopt(recv, ReceiveTimestampns, &true)?;
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
        connect(send, &localhost).unwrap();

        Ok((send, recv))
    }

    #[test]
    fn send_to_simple() -> Result<()> {
        let (send, recv) = new_sockets()?;
        let addr = getsockname::<SockaddrStorage>(recv).unwrap();

        let send_buf = b"njd";
        send_msg(send, send_buf, UDP_MAX_GSO_PACKET_SIZE, 1, None, &addr)?;

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
        send_msg(
            send,
            send_buf,
            UDP_MAX_GSO_PACKET_SIZE,
            1,
            // Invalid because we pass this Instant by the time we call sendmsg()
            Some(Instant::now()),
            &addr,
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
        send_msg(send, send_buf, 1, 6, None, &addr)?;

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
        let addr = getsockname::<SockaddrStorage>(recv).unwrap();

        let send_buf = b"nyj";
        send_msg(
            send,
            send_buf,
            UDP_MAX_GSO_PACKET_SIZE,
            1,
            // Invalid because we pass this Instant by the time we call sendmsg()
            Some(Instant::now()),
            &addr,
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
        let addr = getsockname::<SockaddrStorage>(recv).unwrap();

        let send_buf = b"jets";
        let iov = [IoSlice::new(send_buf)];
        sendmsg(send, &iov, &[], MsgFlags::empty(), Some(&addr))?;

        let mut cmsg_space = cmsg_space!(TimeVal);
        let mut read_buf = [0; 4];

        let recv_data = recv_msg(recv, &mut read_buf, &mut cmsg_space, None)?;

        assert_eq!(recv_data.bytes, 4);
        assert_eq!(&read_buf, b"jets");

        Ok(())
    }
}
