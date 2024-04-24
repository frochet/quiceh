use nix::sys::socket::ControlMessageOwned;
use std::net::SocketAddr;
use std::os::fd::AsFd;
use std::time::Instant;
use std::time::SystemTime;

#[cfg(target_os = "linux")]
use super::linux_imports::*;

// An instant with the value of zero, since [`Instant`] is backed by a version
// of timespec this allows to extract raw values from an [`Instant`]
#[cfg(target_os = "linux")]
const INSTANT_ZERO: Instant = unsafe { std::mem::transmute(0u128) };

#[cfg(target_os = "linux")]
pub fn send_msg(
    fd: impl AsFd, send_buf: &[u8], segment_size: usize, num_pkts: usize,
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

    let borrowed = fd.as_fd();
    sendmsg(
        borrowed.as_raw_fd(),
        &iov,
        &cmsgs,
        MsgFlags::empty(),
        Some(client_addr),
    )
    .map_err(Into::into)
}

/// Receive a message via `recvmsg`.
///
/// # Note
///
/// It is the caller's responsibility to create and clear the cmsg space. `nix`
/// recommends that the space be created via the `cmsg_space!()` macro.
#[cfg(target_os = "linux")]
pub fn recv_msg(
    fd: impl AsFd, read_buf: &mut [u8], cmsg_space: &mut Vec<u8>,
    msg_flags: Option<MsgFlags>,
) -> std::result::Result<RecvData, Errno> {
    use nix::sys::socket::getsockopt;
    use nix::sys::socket::sockopt::RxqOvfl;

    cmsg_space.clear();

    let iov_s = &mut [IoSliceMut::new(read_buf)];
    let msg_flags = msg_flags.unwrap_or(MsgFlags::empty());

    let borrowed = fd.as_fd();
    match recvmsg::<SockaddrStorage>(
        borrowed.as_raw_fd(),
        iov_s,
        Some(cmsg_space),
        msg_flags,
    ) {
        Ok(r) => {
            let bytes = r.bytes;

            let address = match r.address {
                Some(a) => a,
                _ => return Err(Errno::EINVAL),
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

            let mut recv_data = RecvData::new(peer_addr, bytes);

            for msg in r.cmsgs() {
                match msg {
                    ControlMessageOwned::ScmTimestampns(time) =>
                        recv_data.rx_time =
                            SystemTime::UNIX_EPOCH.checked_add(time.into()),
                    ControlMessageOwned::UdpGroSegments(gro) =>
                        recv_data.gro = Some(gro),
                    ControlMessageOwned::RxqOvfl(c) => {
                        if let Ok(1) = getsockopt(&borrowed, RxqOvfl) {
                            recv_data.metrics = Some(RecvMetrics {
                                udp_packets_dropped: c as u64,
                            });
                        }
                    },
                    _ => return Err(Errno::EINVAL),
                }
            }

            Ok(recv_data)
        },
        Err(e) => Err(e),
    }
}

/// Output of a `recvmsg` call.
pub struct RecvData {
    /// The number of bytes which `recvmsg` returned.
    pub bytes: usize,
    /// The peer address for this message.
    pub peer_addr: Option<SocketAddr>,
    /// Metrics for this `recvmsg` call.
    ///
    /// If no valid metrics exist - for example, when the RXQOVFL sockopt is not
    /// set - this will be `None` to prevent confusion when parsing metrics.
    pub metrics: Option<RecvMetrics>,
    /// The `UDP_GRO_SEGMENTS` control message from the result of `recvmsg`, if
    /// it exist.
    pub gro: Option<u16>,
    /// The RX_TIME control message from the result of `recvmsg`, if it exists.
    pub rx_time: Option<SystemTime>,
}

impl RecvData {
    pub fn new(peer_addr: Option<SocketAddr>, bytes: usize) -> Self {
        Self {
            peer_addr,
            bytes,
            metrics: None,
            gro: None,
            rx_time: None,
        }
    }
}

/// Metrics for `recvmsg` calls.
#[derive(Default)]
pub struct RecvMetrics {
    /// The number of packets dropped between the last received packet and this
    /// one.
    ///
    /// See SO_RXQOVFL for more.
    pub udp_packets_dropped: u64,
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use nix::cmsg_space;
    use nix::sys::socket::sockopt::ReceiveTimestampns;
    use nix::sys::socket::sockopt::UdpGroSegment;
    use nix::sys::socket::*;
    use nix::sys::time::TimeVal;
    use std::io::IoSliceMut;
    use std::io::Result;
    use std::os::fd::OwnedFd;
    use std::str::FromStr;

    use super::*;

    const UDP_MAX_GSO_PACKET_SIZE: usize = 65507;

    fn new_sockets() -> Result<(OwnedFd, OwnedFd)> {
        let recv = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            SockProtocol::Udp,
        )
        .unwrap();
        setsockopt(&recv, ReceiveTimestampns, &true)?;
        setsockopt(&recv, UdpGroSegment, &true)?;
        let localhost = SockaddrIn::from_str("127.0.0.1:0").unwrap();
        bind(recv.as_raw_fd(), &localhost).unwrap();

        let send = socket(
            AddressFamily::Inet,
            SockType::Datagram,
            SockFlag::empty(),
            SockProtocol::Udp,
        )
        .unwrap();
        connect(send.as_raw_fd(), &localhost).unwrap();

        Ok((send, recv))
    }

    #[test]
    fn send_to_simple() -> Result<()> {
        let (send, recv) = new_sockets()?;
        let addr = getsockname::<SockaddrStorage>(recv.as_raw_fd()).unwrap();

        let send_buf = b"njd";
        send_msg(send, send_buf, UDP_MAX_GSO_PACKET_SIZE, 1, None, &addr)?;

        let mut buf = [0; 3];
        let mut read_buf = [IoSliceMut::new(&mut buf)];
        let recv = recvmsg::<()>(
            recv.as_raw_fd(),
            &mut read_buf,
            None,
            MsgFlags::empty(),
        )
        .unwrap();

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
        let addr = getsockname::<SockaddrStorage>(recv.as_raw_fd()).unwrap();

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
        let recv = recvmsg::<()>(
            recv.as_raw_fd(),
            &mut read_buf,
            None,
            MsgFlags::empty(),
        )
        .unwrap();

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
        let addr = getsockname::<SockaddrStorage>(recv.as_raw_fd()).unwrap();

        let send_buf = b"devils";
        send_msg(send, send_buf, 1, 6, None, &addr)?;

        let mut buf = [0; 6];
        let mut read_buf = [IoSliceMut::new(&mut buf)];
        let mut x = cmsg_space!(u32);
        let recv = recvmsg::<()>(
            recv.as_raw_fd(),
            &mut read_buf,
            Some(&mut x),
            MsgFlags::empty(),
        )
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
        let addr = getsockname::<SockaddrStorage>(recv.as_raw_fd()).unwrap();

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

        let recv = recvmsg::<()>(
            recv.as_raw_fd(),
            &mut read_buf,
            None,
            MsgFlags::empty(),
        )
        .unwrap();

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
        let addr = getsockname::<SockaddrStorage>(recv.as_raw_fd()).unwrap();

        let send_buf = b"jets";
        let iov = [IoSlice::new(send_buf)];
        sendmsg(send.as_raw_fd(), &iov, &[], MsgFlags::empty(), Some(&addr))?;

        let mut cmsg_space = cmsg_space!(TimeVal);
        let mut read_buf = [0; 4];

        let recv_data = recv_msg(recv, &mut read_buf, &mut cmsg_space, None)?;

        assert_eq!(recv_data.bytes, 4);
        assert_eq!(&read_buf, b"jets");

        Ok(())
    }
}
