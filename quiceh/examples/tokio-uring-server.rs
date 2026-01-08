/// Tokio-uring example using quiceh.
///
/// This example is _NOT_ a performance optimal approach.

#[macro_use]
extern crate log;

use std::collections::HashMap;
use std::net;
use std::sync::Arc;

use ring::rand::*;

use tokio::sync::mpsc;
use tokio_uring::buf::fixed::{FixedBuf, FixedBufPool};
use tokio_uring::buf::BoundedBuf;

use quiceh::BufFactory;
use quiceh::BufSplit;

use clap::Parser;

const MAX_DATAGRAM_SIZE: usize = 1350;
const MAX_MESSAGE_SIZE: usize = 65536;

#[derive(Debug, Clone, Default)]
struct MyBufFactory;

#[derive(Debug, Clone, Default)]
struct MyBuf {
    inner: Arc<Box<[u8]>>,
    start: usize,
    end: usize,
}

impl MyBuf {
    fn new(inner: Arc<Box<[u8]>>, start: usize, end: usize) -> Self {
        Self { inner, start, end }
    }

    fn len(&self) -> usize {
        self.end - self.start
    }
}

impl From<Vec<u8>> for MyBuf {
    fn from(value: Vec<u8>) -> Self {
        MyBuf {
            start: 0,
            end: value.len(),
            inner: Arc::new(value.into_boxed_slice()),
        }
    }
}

impl BufFactory for MyBufFactory {
    type Buf = MyBuf;

    fn buf_from_slice(buf: &[u8]) -> Self::Buf {
        MyBuf {
            start: 0,
            end: buf.len(),
            inner: Arc::new(buf.into()),
        }
    }
}

impl BufSplit for MyBuf {
    fn split_at(&mut self, at: usize) -> Self {
        assert!(at <= self.len(), "split_at index out of bounds");

        let newend = self.start + at;
        let buf = MyBuf::new(self.inner.clone(), newend, self.end);

        self.end = newend;

        buf
    }
}

impl AsRef<[u8]> for MyBuf {
    fn as_ref(&self) -> &[u8] {
        &self.inner[self.start..self.end]
    }
}

struct PartialResponse {
    chunk: MyBuf,
    remaining_chunk: Option<MyBuf>,
    written: usize,
    tot_size: usize,
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    with_retry: bool,
}

type ClientMap = HashMap<
    quiceh::ConnectionId<'static>,
    mpsc::UnboundedSender<(FixedBuf, usize, net::SocketAddr)>,
>;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    tokio_uring::start(async {
        env_logger::builder().format_timestamp_nanos().init();

        let args = Args::parse();

        let socket = Arc::new(
            tokio_uring::net::UdpSocket::bind("127.0.0.1:4433".parse().unwrap())
                .await
                .unwrap(),
        );
        let mut pacing = false;
        if set_txtime_sockopt(&socket) {
            pacing = true;
            debug!("successfully set SO_TXTIME socket option");
        } else {
            debug!("setsockopt failed");
        }

        if !set_gso(&socket, MAX_DATAGRAM_SIZE) {
            debug!("Could not set GSO's max segment size");
        }

        // Create the configuration for the QUIC connections.
        let mut config =
            quiceh::Config::new(quiceh::PROTOCOL_VERSION_VREVERSO).unwrap();
        config
            .load_cert_chain_from_pem_file("quiceh/examples/cert.crt")
            .unwrap();
        config
            .load_priv_key_from_pem_file("quiceh/examples/cert.key")
            .unwrap();
        config
            .set_application_protos(&[
                b"hq-interop",
                b"hq-29",
                b"hq-28",
                b"hq-27",
                b"http/0.9",
            ])
            .unwrap();
        config.discover_pmtu(false);
        config.set_max_idle_timeout(5000);
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);

        config.set_initial_congestion_window_packets(10);
        config.set_max_connection_window(25_165_824);
        config.set_max_stream_window(16_777_216);
        config.enable_early_data();
        // XXX  We're not using it when enabled
        config.enable_pacing(pacing);
        config.enable_hidden_copy_for_zc_sender(false);

        let rng = SystemRandom::new();
        let conn_id_seed =
            ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

        let mut clients = ClientMap::new();
        let (tx_garbage_conn, mut rx_garbage_conn) = mpsc::channel(128);

        let pool = FixedBufPool::new(
            std::iter::repeat_with(|| vec![0; MAX_MESSAGE_SIZE])
                .take(20)
                .chain(
                    std::iter::repeat_with(|| vec![0; MAX_DATAGRAM_SIZE])
                        .take(20),
                ),
        );

        pool.register()?;

        loop {
            let buf = pool.next(MAX_MESSAGE_SIZE).await;
            tokio::select! {
                Some(scid) = rx_garbage_conn.recv() => {
                    let scid = quiceh::ConnectionId::from_vec(scid);
                    clients.remove(&scid);
                }

                (result, mut buf) = socket.recv_from(buf) => {

                    let (len, from) = result.unwrap();
                    let pkt_buf = &mut buf[..len];

                    let hdr = match quiceh::Header::from_slice(
                        pkt_buf,
                        quiceh::MAX_CONN_ID_LEN,
                    ) {
                        Ok(v) => v,
                        Err(e) => {
                            error!("Parsing packet header failed: {:?}", e);
                            continue;
                        },
                    };

                    trace!("got packet {:?}", hdr);

                    let conn_id = ring::hmac::sign(&conn_id_seed, &hdr.dcid);
                    let conn_id = &conn_id.as_ref()[..quiceh::MAX_CONN_ID_LEN];
                    let conn_id = conn_id.to_vec().into();

                    let client_sender = if !clients.contains_key(&hdr.dcid) &&
                        !clients.contains_key(&conn_id)
                    {
                        if hdr.ty != quiceh::Type::Initial {
                            error!("Packet is not Initial");
                            continue;
                        }

                        if !quiceh::version_is_supported(hdr.version) {
                            warn!("Doing version negotiation");

                            let mut out = pool.next(MAX_DATAGRAM_SIZE).await;
                            let len =
                                quiceh::negotiate_version(&hdr.scid, &hdr.dcid, &mut out[..])
                                    .unwrap();
                            if let (Err(e), _) = socket.send_to(out.slice(0..len), from).await {
                                if e.kind() == std::io::ErrorKind::WouldBlock {
                                    debug!("send() would block");
                                    break;
                                }
                                panic!("send() failed: {:?}", e);
                            }
                            continue;
                        }

                        let mut scid = [0; quiceh::MAX_CONN_ID_LEN];
                        scid.copy_from_slice(&conn_id);

                        let mut odcid = None;

                        if args.with_retry {
                            let token = hdr.token.as_ref().unwrap();

                            if token.is_empty() {
                                warn!("Doing stateless retry");
                                let scid = quiceh::ConnectionId::from_ref(&scid);
                                let new_token = mint_token(&hdr, &from);
                                let mut out = pool.next(MAX_DATAGRAM_SIZE).await;
                                let len = quiceh::retry(
                                    &hdr.scid,
                                    &hdr.dcid,
                                    &scid,
                                    &new_token,
                                    hdr.version,
                                    &mut out[..],
                                )
                                .unwrap();
                                if let (Err(e), _) = socket.send_to(out.slice(0..len), from).await {
                                    if e.kind() == std::io::ErrorKind::WouldBlock {
                                        debug!("send() would block");
                                        break;
                                    }
                                    panic!("send() failed: {:?}", e);
                                }
                                continue;
                            }
                            odcid = validate_token(&from, token);
                            if odcid.is_none() {
                                error!("Invalid address validation token");
                                continue;
                            }

                            if scid.len() != hdr.dcid.len() {
                                error!("Invalid destination connection ID");
                                continue;
                            }

                            // Reuse the source connection ID we sent in the Retry
                            // packet, instead of changing it again.
                            scid.copy_from_slice(&hdr.dcid);

                        }


                        let scid = quiceh::ConnectionId::from_vec(scid.to_vec());

                        debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

                        let conn = quiceh::accept_with_buf_factory::<MyBufFactory>(
                            &scid,
                            odcid.as_ref(),
                            socket.local_addr().unwrap(),
                            from,
                            &mut config,
                        )
                        .unwrap();

                        let (tx, rx) = mpsc::unbounded_channel();

                        tokio_uring::spawn(handle_client(
                            socket.clone(),
                            conn,
                            rx,
                            tx_garbage_conn.clone(),
                            pool.clone(),
                        ));

                        clients.insert(scid.clone(), tx.clone());
                        Some(tx)
                    } else {
                        clients.get(&hdr.dcid).or_else(|| clients.get(&conn_id)).cloned()
                    };

                    if let Some(client_sender) = client_sender {
                        if let Err(e) = client_sender.send((buf, len, from)) {
                            error!("Failed to send packet to client handler: {}", e);
                        }
                    }
                }
            }
        }
        Ok(())
    })
}

async fn handle_client<T: tokio_uring::buf::IoBufMut>(
    socket: Arc<tokio_uring::net::UdpSocket>,
    mut conn: quiceh::Connection<MyBufFactory>,
    mut rx: mpsc::UnboundedReceiver<(FixedBuf, usize, net::SocketAddr)>,
    tx_garbage_conn: mpsc::Sender<Vec<u8>>, pool: FixedBufPool<T>,
) {
    let mut partial_responses: HashMap<u64, PartialResponse> = HashMap::new();

    let mut loss_rate: f64 = 0.0;
    let mut max_send_burst = 48 * MAX_DATAGRAM_SIZE;

    let mut continue_write = false;
    // TODO: NO TxTime support; (should use sendmsg_zc with appropriate message
    // control)

    loop {
        let timeout = {
            if continue_write {
                Some(std::time::Duration::from_secs(0))
            } else {
                conn.timeout()
            }
        };

        tokio::select! {

            _ = tokio::time::sleep(timeout.unwrap_or(std::time::Duration::from_secs(1))) => {
                debug!(
                    "{} timeout occured",
                    conn.trace_id(),
                );
                if !continue_write {
                    conn.on_timeout();
                } else {
                    for stream_id in conn.writable() {
                        handle_writable(&mut conn, stream_id, &mut partial_responses);
                    }
                }
            }

            Some((mut buf, len, from)) = rx.recv() => {
                let recv_info = quiceh::RecvInfo {
                    to: socket.local_addr().unwrap(),
                    from,
                };

                let pkt = &mut buf[..len];

                let read = match conn.recv(pkt, recv_info) {
                    Ok(v) => v,
                    Err(e) => {
                        error!("{} recv failed: {:?}", conn.trace_id(), e);
                        break;
                    },
                };

                debug!("{} processed {} bytes", conn.trace_id(), read);

                if conn.is_in_early_data() || conn.is_established() {
                    let readable: Vec<u64> = conn.readable().collect();
                    for s in readable {
                        while let Ok((chunk, fin)) = conn.stream_recv_zc(s) {
                            debug!("{} received {} bytes", conn.trace_id(), chunk.len());
                            debug!(
                                "{} stream {} has {} bytes (fin? {})",
                                conn.trace_id(),
                                s,
                                chunk.len(),
                                fin
                            );

                            let response = handle_stream(&chunk[..], ".").await;
                            let fin = response.body.len() == response.tot_size;
                            debug!("Starting sending body part of {} for total size {}, fin is {}", response.body.len(), response.tot_size, fin);
                            let body_len = response.body.len();
                            let (written, remaining) = match conn.stream_send_zc(s, response.body.clone(), Some(body_len), fin) {
                                Ok(v) => v,
                                Err(quiceh::Error::Done) => (0, None),
                                Err(e) => {
                                    error!("{} stream send failed {:?}", conn.trace_id(), e);
                                    break;
                                },
                            };

                            if written < response.tot_size {
                                debug!("{} written partially on stream {} bytes", conn.trace_id(), written);
                                partial_responses.insert(s, PartialResponse {
                                    chunk: response.body,
                                    remaining_chunk: remaining,
                                    written,
                                    tot_size: response.tot_size,
                                });
                            }
                        }
                    }

                    for stream_id in conn.writable() {
                        handle_writable(&mut conn, stream_id, &mut partial_responses);
                    }
                }
            }
        }
        continue_write = false;
        let mut total_write = 0;
        let mut dst_info = None;
        let mut out = pool.next(MAX_MESSAGE_SIZE).await;
        let new_max_send_burst = {
            // Reduce max_send_burst by 25% if loss is increasing more than 0.1%.
            let new_loss_rate =
                conn.stats().lost as f64 / conn.stats().sent as f64;
            if new_loss_rate > loss_rate + 0.001 {
                max_send_burst = max_send_burst / 4 * 3;
                // Minimun bound of 10xMSS.
                max_send_burst = max_send_burst.max(MAX_DATAGRAM_SIZE * 10);
                loss_rate = new_loss_rate;
            }

            let new_max_send_burst = max_send_burst;

            'send: while total_write < new_max_send_burst {
                let (write, send_info) =
                    match conn.send(&mut out[total_write..new_max_send_burst]) {
                        Ok(v) => v,

                        Err(quiceh::Error::Done) => {
                            debug!("{} done writing", conn.trace_id());
                            break 'send;
                        },
                        Err(e) => {
                            debug!("{} send failed: {:?}", conn.trace_id(), e);
                            conn.close(false, 0x1, b"fail").ok();
                            break;
                        },
                    };

                total_write += write;

                let _ = dst_info.get_or_insert(send_info);

                if write < MAX_DATAGRAM_SIZE {
                    continue_write = true;
                    break 'send;
                }
            }
            new_max_send_burst
        };

        if total_write != 0 && dst_info.is_some() {
            debug!("Sending {} bytes in socket", total_write);
            // For some reason send_to is faster than sendmsg_zc ...
            let (res, ..) = socket.send_to(out.slice(0..total_write), dst_info.unwrap().to)
//                send_zc_to(&socket, dst_info.unwrap(), out.slice(0..total_write))
                    .await;

            match res {
                Ok(v) => {
                    if v < total_write {
                        info!("Wrote {} out of {}", v, total_write);
                    }
                },
                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        trace!("send() would block");
                        continue;
                    }

                    panic!("send_to() failed: {:?}", e);
                },
            };
        }

        if total_write >= new_max_send_burst {
            continue_write = true;
        }

        let (is_closed, scid) = {
            if conn.is_closed() {
                (true, Some(conn.source_id().as_ref().to_vec()))
            } else {
                (false, None)
            }
        };

        if is_closed {
            debug!(
                "Conn closed: sending {}",
                scid.clone()
                    .unwrap()
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join("")
            );
            tx_garbage_conn
                .send(scid.unwrap())
                .await
                .expect("failed to close connection");
            break;
        }
    }
}

/// This is an example. A deterministic token isn't a great idea for production;
/// don't re-use this.
fn mint_token(hdr: &quiceh::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();
    token.extend_from_slice(b"quiceh");
    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };
    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);
    token
}

/// Provides no cryptographic validation whatsoever. It is only example code.
fn validate_token<'a>(
    src: &net::SocketAddr, token: &'a [u8],
) -> Option<quiceh::ConnectionId<'a>> {
    if token.len() < 6 {
        return None;
    }
    if &token[..6] != b"quiceh" {
        return None;
    }
    let token = &token[6..];
    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };
    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }
    Some(quiceh::ConnectionId::from_ref(&token[addr.len()..]))
}

struct Response {
    body: MyBuf,
    tot_size: usize,
}

async fn handle_stream(buf: &[u8], root: &str) -> Response {
    if buf.starts_with(b"GET ") {
        let uri = &buf[4..buf.len()];
        let uri = String::from_utf8(uri.to_vec()).unwrap();
        let uri = String::from(uri.lines().next().unwrap());
        let uri = std::path::Path::new(&uri);
        let mut path = std::path::PathBuf::from(root);
        for c in uri.components() {
            if let std::path::Component::Normal(v) = c {
                path.push(v)
            }
        }
        info!(
            "got GET request for {:?} on stream, with uri {:?}",
            path, uri,
        );

        if uri.starts_with("/download/") {
            let size = uri
                .components()
                .nth(2)
                .and_then(|c| c.as_os_str().to_str())
                .and_then(|s| s.parse::<usize>().ok());
            if let Some(val) = size {
                info!("sending {} bytes back", val);
                let (res, tot_size) = if val < 1024 * 1024 {
                    (vec![42; val], val)
                } else {
                    (vec![42; 1024 * 1024], val)
                };
                Response {
                    body: res.into(),
                    tot_size,
                }
            } else {
                let res = b"Invalid download request!\r\n".to_vec();
                let len = res.len();
                Response {
                    body: res.into(),
                    tot_size: len,
                }
            }
        } else {
            let body = tokio::fs::read(path.as_path())
                .await
                .unwrap_or_else(|_| b"Not Found!\r\n".to_vec());
            info!("sending response of size {} on stream", body.len(),);
            let len = body.len();
            Response {
                body: body.into(),
                tot_size: len,
            }
        }
    } else {
        let res = b"Not a GET request!\r\n".to_vec();
        let len = res.len();
        Response {
            body: res.into(),
            tot_size: len,
        }
    }
}

fn handle_writable(
    conn: &mut quiceh::Connection<MyBufFactory>, stream_id: u64,
    partial_responses: &mut HashMap<u64, PartialResponse>,
) {
    debug!("{} stream {} is writable", conn.trace_id(), stream_id);
    if !partial_responses.contains_key(&stream_id) {
        return;
    }
    let resp = partial_responses.get_mut(&stream_id).unwrap();

    let body = if let Some(rem) = resp.remaining_chunk.take() {
        rem
    } else {
        let upper = (resp.tot_size - resp.written).min(resp.chunk.len());
        let mut b = resp.chunk.clone();
        if upper < b.len() {
            b.split_at(upper);
        }
        b
    };

    let fin = resp.written + body.len() >= resp.tot_size;
    debug!("fin bit is {}", fin);

    let body_len = body.len();
    let (written, remaining) =
        match conn.stream_send_zc(stream_id, body, Some(body_len), fin) {
            Ok(v) => v,
            Err(quiceh::Error::Done) => (0, None),
            Err(e) => {
                partial_responses.remove(&stream_id);
                error!("{} stream send failed {:?}", conn.trace_id(), e);
                return;
            },
        };

    debug!(
        "{} written partially on stream {} bytes",
        conn.trace_id(),
        written
    );
    resp.written += written;
    resp.remaining_chunk = remaining;

    if resp.written == resp.tot_size {
        partial_responses.remove(&stream_id);
    }
}

#[allow(dead_code)]
async fn send_zc_to<T: BoundedBuf>(
    on: &tokio_uring::net::UdpSocket, send_info: quiceh::SendInfo, buf: T,
) -> (std::io::Result<usize>, T) {
    let mut io_slices = Vec::new();
    io_slices.push(buf);

    let (res, mut buf, _) = on
        .sendmsg_zc(io_slices, Some(send_info.to), None::<T>)
        .await;
    (res, buf.pop().unwrap())
}

/// Set SO_TXTIME socket option.
///
/// This socket option is set to send to kernel the outgoing UDP
/// packet transmission time in the sendmsg syscall.
///
/// Note that this socket option works only on linux platforms.
fn set_txtime_sockopt(sock: &tokio_uring::net::UdpSocket) -> bool {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::TxTime;
    use std::os::fd::AsRawFd;

    let config = nix::libc::sock_txtime {
        clockid: libc::CLOCK_MONOTONIC,
        flags: 0,
    };

    let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(sock.as_raw_fd()) };

    setsockopt(&fd, TxTime, &config).is_ok()
}
/// Set Udp GSO segment size
///
/// This socket option is set to send to kernel the outgoing UDP
/// packet transmission time in the sendmsg syscall.
///
/// Note that this socket option works only on linux platforms.
pub fn set_gso(
    socket: &tokio_uring::net::UdpSocket, segment_size: usize,
) -> bool {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::UdpGsoSegment;
    use std::os::unix::io::AsRawFd;

    let fd = unsafe { std::os::fd::BorrowedFd::borrow_raw(socket.as_raw_fd()) };

    setsockopt(&fd, UdpGsoSegment, &(segment_size as i32)).is_ok()
}
