#[macro_use]
extern crate log;

use std::collections::HashMap;
use std::net;
use std::sync::Arc;

use ring::rand::*;

use quiceh::AppRecvBufMap;
use quinn_udp::Transmit;
use quinn_udp::UdpSocketState;
use tokio::sync::mpsc;

use clap::Parser;

const MAX_DATAGRAM_SIZE: usize = 1350;

struct PartialResponse {
    body: Vec<u8>,
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
    mpsc::Sender<(Vec<u8>, net::SocketAddr)>,
>;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    env_logger::builder().format_timestamp_nanos().init();

    let args = Args::parse();

    let socket =
        Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:4433").await.unwrap());
    let mut pacing = false;
    match set_txtime_sockopt(&socket) {
        Ok(_) => {
            pacing = true;
            debug!("successfully set SO_TXTIME socket option");
        },
        Err(e) => debug!("setsockopt failed {:?}", e),
    };

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
    config.enable_pacing(pacing);
    config.enable_hidden_copy_for_zc_sender(false);

    let rng = SystemRandom::new();
    let conn_id_seed =
        ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

    let mut clients = ClientMap::new();
    let (tx_garbage_conn, mut rx_garbage_conn) = mpsc::channel(128);

    let mut buf = vec![0; 65535];

    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(scid) = rx_garbage_conn.recv() => {
                    let scid = quiceh::ConnectionId::from_vec(scid);
                    clients.remove(&scid);
                }

                result = socket.recv_from(&mut buf) => {
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

                            let mut out = [0; MAX_DATAGRAM_SIZE];
                            let len =
                                quiceh::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                                    .unwrap();
                            let out = &out[..len];
                            if let Err(e) = socket.send_to(out, from).await {
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

                        // TODO add CLAP and CLAP param
                        if args.with_retry {
                            let token = hdr.token.as_ref().unwrap();

                            if token.is_empty() {
                                warn!("Doing stateless retry");
                                let scid = quiceh::ConnectionId::from_ref(&scid);
                                let new_token = mint_token(&hdr, &from);
                                let mut out = [0; MAX_DATAGRAM_SIZE];
                                let len = quiceh::retry(
                                    &hdr.scid,
                                    &hdr.dcid,
                                    &scid,
                                    &new_token,
                                    hdr.version,
                                    &mut out,
                                )
                                .unwrap();
                                let out = &out[..len];
                                if let Err(e) = socket.send_to(out, from).await {
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

                        let conn = quiceh::accept(
                            &scid,
                            odcid.as_ref(),
                            socket.local_addr().unwrap(),
                            from,
                            &mut config,
                        )
                        .unwrap();

                        let (tx, rx) = mpsc::channel(128);

                        tokio::spawn(handle_client(
                            socket.clone(),
                            conn,
                            rx,
                            tx_garbage_conn.clone(),
                            socket.local_addr().unwrap(),
                        ));

                        clients.insert(scid.clone(), tx.clone());
                        Some(tx)
                    } else {
                        clients.get(&hdr.dcid).or_else(|| clients.get(&conn_id)).cloned()
                    };

                    if let Some(client_sender) = client_sender {
                        if let Err(e) = client_sender.send((pkt_buf.to_vec(), from)).await {
                            error!("Failed to send packet to client handler: {}", e);
                        }
                    }
                }
            }
        }
    });
    handle.await.unwrap();
}

async fn handle_client(
    socket: Arc<tokio::net::UdpSocket>, mut conn: quiceh::Connection,
    mut rx: mpsc::Receiver<(Vec<u8>, net::SocketAddr)>,
    tx_garbage_conn: mpsc::Sender<Vec<u8>>, local_addr: net::SocketAddr,
) {
    let mut app_buffers = AppRecvBufMap::new(3, 1_000_000, 1_000_000);
    let mut partial_responses: HashMap<u64, PartialResponse> = HashMap::new();
    let mut out = vec![0; 65535];
    let mut loss_rate: f64 = 0.0;
    let mut max_send_burst = 65535;
    let send_state = UdpSocketState::new((&socket).into()).unwrap();
    send_state
        .set_send_buffer_size((&socket).into(), 2097152)
        .unwrap();

    let mut continue_write = false;
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

            Some((mut pkt, from)) = rx.recv() => {
                let recv_info = quiceh::RecvInfo {
                    to: socket.local_addr().unwrap(),
                    from,
                };

                let read = match conn.recv(&mut pkt, &mut app_buffers, recv_info) {
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
                        while let Ok((chunk, fin)) = conn.stream_recv_zc(s, &mut app_buffers) {
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
                            let written = match conn.stream_send(s, &response.body, fin) {
                                Ok(v) => v,
                                Err(quiceh::Error::Done) => 0,
                                Err(e) => {
                                    error!("{} stream send failed {:?}", conn.trace_id(), e);
                                    break;
                                },
                            };

                            if written < response.tot_size {
                                debug!("{} written partially on stream {} bytes", conn.trace_id(), written);
                                partial_responses.insert(s, PartialResponse {
                                    body: response.body,
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

            let new_max_send_burst = conn.send_quantum().min(max_send_burst)
                / MAX_DATAGRAM_SIZE
                * MAX_DATAGRAM_SIZE;

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
            let transmit = Transmit {
                destination: dst_info.unwrap().to,
                ecn: None,
                contents: &out[..total_write],
                segment_size: Some(MAX_DATAGRAM_SIZE),
                src_ip: Some(local_addr.ip()),
            };

            if let Err(e) = send_state.send((&socket).into(), &transmit) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    trace!("send() would block");
                    continue;
                }

                panic!("send_to() failed: {:?}", e);
            }
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
            tx_garbage_conn.send(scid.unwrap()).await.unwrap();
            break;
        }
    }
}

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
    body: Vec<u8>,
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
                    body: res,
                    tot_size,
                }
            } else {
                let res = b"Invalid download request!\r\n".to_vec();
                let len = res.len();
                Response {
                    body: res,
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
                body,
                tot_size: len,
            }
        }
    } else {
        let res = b"Not a GET request!\r\n".to_vec();
        let len = res.len();
        Response {
            body: res,
            tot_size: len,
        }
    }
}

fn handle_writable(
    conn: &mut quiceh::Connection, stream_id: u64,
    partial_responses: &mut HashMap<u64, PartialResponse>,
) {
    debug!("{} stream {} is writable", conn.trace_id(), stream_id);
    if !partial_responses.contains_key(&stream_id) {
        return;
    }
    let resp = partial_responses.get_mut(&stream_id).unwrap();
    let body = if resp.written < resp.body.len() {
        &resp.body[resp.written..]
    } else {
        let upper = (resp.tot_size - resp.written).min(resp.body.len());
        &resp.body[..upper]
    };

    let fin = body.len() >= resp.tot_size - resp.written;
    debug!("fin bit is {}", fin);
    let written = match conn.stream_send(stream_id, body, fin) {
        Ok(v) => v,
        Err(quiceh::Error::Done) => 0,
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
    if resp.written == resp.tot_size {
        partial_responses.remove(&stream_id);
    }
}

/// Set SO_TXTIME socket option.
///
/// This socket option is set to send to kernel the outgoing UDP
/// packet transmission time in the sendmsg syscall.
///
/// Note that this socket option works only on linux platforms.
fn set_txtime_sockopt(sock: &tokio::net::UdpSocket) -> std::io::Result<()> {
    use nix::sys::socket::setsockopt;
    use nix::sys::socket::sockopt::TxTime;

    let config = nix::libc::sock_txtime {
        clockid: libc::CLOCK_MONOTONIC,
        flags: 0,
    };

    setsockopt(sock, TxTime, &config)?;

    Ok(())
}
