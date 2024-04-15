use nix::sys::socket::ControlMessage;
use smallvec::SmallVec;

fn send_to() {
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

        let addr = SockaddrStorage::from(client_addr);

        // Must use [`try_io`] so tokio can properly clear its readyness flag
        let res = socket.try_io(Interest::WRITABLE, || {
            let fd = socket.as_raw_fd();
            sendmsg(fd, &iov, &cmsgs, MsgFlags::empty(), Some(&addr))
                .map_err(Into::into)
        });

        match res {
            // Wait for the socket to become writable and try again
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                socket.writable().await?
            },
            res => return res,
        }
    }
}
