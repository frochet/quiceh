mod bench_util;
use criterion::black_box;
use criterion::criterion_group;
use criterion::criterion_main;
use criterion::BatchSize;
use criterion::BenchmarkId;
use criterion::Criterion;
use criterion::Throughput;
use quiche::h3::testing::Session;
use quiche::h3::Header;
use quiche::h3::NameValue;
use itertools::Itertools;

use bench_util::*;

const NUMBER_OF_REQUESTS: u32 = 80;
const MAX_DATAGRAM_SIZE: usize = 1350;

#[derive(Default)]
pub struct StreamIdHasher {
    id: u64,
}

impl std::hash::Hasher for StreamIdHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.id
    }

    #[inline]
    fn write_u64(&mut self, id: u64) {
        self.id = id;
    }

    #[inline]
    fn write(&mut self, _: &[u8]) {
        // We need a default write() for the trait but stream IDs will always
        // be a u64 so we just delegate to write_u64.
        unimplemented!()
    }
}

type BuildStreamIdHasher = std::hash::BuildHasherDefault<StreamIdHasher>;

type StreamIdHashMap<V> =
    std::collections::HashMap<u64, V, BuildStreamIdHasher>;

// Process 157 packets at a time to roughly match the MAX RCV_BUF
pub const BATCH_PACKETS_SIZE: usize = 157;

fn bench_h3(
    s: &mut Session, flight: &mut Vec<(Vec<u8>, quiche::SendInfo)>,
    response_map: &mut StreamIdHashMap<Vec<u8>>,
) {
    // Simulate the receiver receiving BATCH_PACKETS_SIZE
    // from the OS, and then feeding it to QUIC, and eventually
    // polling HTTP/3 data.
    for chunk in &flight.into_iter().chunks(BATCH_PACKETS_SIZE) {
        for &mut (ref mut pkt, ref mut si) in chunk {
            let info = quiche::RecvInfo {
                to: si.to,
                from: si.from,
            };
            s.pipe
                .client
                .recv(pkt, &mut s.pipe.client_app_buffers, info)
                .unwrap();
        }
        // polling!
        let mut res_count = 0;

        loop {
            match s.client.poll(&mut s.pipe.client) {
                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                    let s = std::str::from_utf8(list[2].value()).unwrap();
                    let content_length = s.parse().unwrap();
                    // update the map with a fully allocated app receive buffer.
                    response_map.insert(stream_id, vec![0; content_length]);
                },
                Ok((stream_id, quiche::h3::Event::Data)) => {
                    s.recv_body_client(
                        stream_id,
                        response_map.get_mut(&stream_id).unwrap(),
                    )
                    .unwrap();
                    black_box(response_map.get(&stream_id).unwrap());
                },
                Ok((_, quiche::h3::Event::Finished)) => {
                    res_count += 1;
                    if res_count == NUMBER_OF_REQUESTS {
                        break; // we're done.
                    }
                },
                Err(quiche::h3::Error::Done) => {
                    res_count += 1;
                    if res_count == NUMBER_OF_REQUESTS {
                        break; // we're done.
                    }
                }
                _ => (),
            }
        }
    }
}

fn bench_h3_quicv3(
    s: &mut Session, flight: &mut Vec<(Vec<u8>, quiche::SendInfo)>,
) {
    for chunk in &flight.into_iter().chunks(BATCH_PACKETS_SIZE) {
        for &mut (ref mut pkt, ref mut si) in chunk {
            let info = quiche::RecvInfo {
                to: si.to,
                from: si.from,
            };
            s.pipe
                .client
                .recv(pkt, &mut s.pipe.client_app_buffers, info)
                .unwrap();
        }
        // polling!
        let mut res_count = 0;

        loop {
            match s
                .client
                .poll_v3(&mut s.pipe.client, &mut s.pipe.client_app_buffers)
            {
                Ok((stream_id, quiche::h3::Event::Data)) => {
                    let (b, tot_exp_len) = s.recv_body_v3_client(stream_id).unwrap();
                    let len = b.len();
                    s.body_consumed_client(stream_id, len).unwrap();
                },
                Ok((_, quiche::h3::Event::Finished)) => {
                    res_count += 1;
                    if res_count == NUMBER_OF_REQUESTS {
                        break; // we're done.
                    }
                },
                Err(quiche::h3::Error::Done) => {
                    res_count += 1;
                    if res_count == NUMBER_OF_REQUESTS {
                        break; // we're done.
                    }
                }
                _ => (),
            }
        }
    }
}

fn criterion_benchmark(c: &mut Criterion<CPUTime>) {
    let mut config_v1 = quiche::Config::new(quiche::PROTOCOL_VERSION_V1).unwrap();
    let mut config_v3 = quiche::Config::new(quiche::PROTOCOL_VERSION_V3).unwrap();
    config_v1
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config_v1
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config_v1
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config_v1.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config_v1.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config_v1.set_initial_max_data(10_000_000_000);
    config_v1.set_max_stream_window(25_165_824);
    config_v1.set_initial_max_stream_data_uni(10_000_000_000);
    config_v1.set_initial_max_streams_bidi(10_000_000_000);
    config_v1.set_initial_max_stream_data_bidi_local(10_000_000_000);
    config_v1.set_initial_max_stream_data_bidi_remote(10_000_000_000);
    config_v1.set_initial_max_streams_bidi(10000);
    config_v1.set_initial_max_streams_uni(10000);
    config_v1.set_initial_congestion_window_packets(1_000_000); // Dr.Evil's choice
    config_v1.verify_peer(false);

    config_v3
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config_v3
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config_v3
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config_v3.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config_v3.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config_v3.set_initial_max_data(10_000_000_000);
    config_v3.set_max_stream_window(25_165_824);
    config_v3.set_initial_max_stream_data_uni(10_000_000_000);
    config_v3.set_initial_max_streams_bidi(10_000_000_000);
    config_v3.set_initial_max_stream_data_bidi_local(10_000_000_000);
    config_v3.set_initial_max_stream_data_bidi_remote(10_000_000_000);
    config_v3.set_initial_max_streams_bidi(10_000);
    config_v3.set_initial_max_streams_uni(10_000);
    config_v3.set_initial_congestion_window_packets(1_000_000);
    config_v3.verify_peer(false);

    let h3_config = quiche::h3::Config::new().unwrap();

    let mut group = c.benchmark_group("H3_Recv_path");
    let sendbuf = vec![0; 31250];
    group.throughput(Throughput::Bytes(2_500_000));

    group.bench_with_input(
        BenchmarkId::new("H3_with_QUIC_V3", 2_500_000),
        &sendbuf,
        |b, sendbuf| {
            b.iter_batched_ref(
                || {
                    // init called for each run
                    let mut s = Session::with_configs(&mut config_v3, &h3_config)
                        .unwrap();
                    s.handshake().unwrap();
                    let mut response_map = StreamIdHashMap::default();
                    let resp = vec![
                        Header::new(b":status", b"200"),
                        Header::new(b"server", b"quiche-test"),
                        Header::new(b"content-length", b"31250"),
                    ];

                    for _ in 0..NUMBER_OF_REQUESTS {
                        let (stream_id, _) = s.send_request(true).unwrap();
                        response_map.insert(stream_id, Vec::<u8>::new());
                        s.poll_server().unwrap(); // headers
                        s.poll_server().unwrap(); // finished event
                    }

                    for stream_id in response_map.keys() {
                        s.server
                            .send_response(
                                &mut s.pipe.server,
                                *stream_id,
                                &resp,
                                false,
                            )
                            .unwrap();
                        s.server
                            .send_body(
                                &mut s.pipe.server,
                                *stream_id,
                                &sendbuf,
                                true,
                            )
                            .unwrap();
                    }
                    // let's catch flying packets
                    let flight =
                        quiche::testing::emit_flight(&mut s.pipe.server).unwrap();
                    (s, flight)
                },
                // Benched code for each sample
                |(ref mut s, flight)| bench_h3_quicv3(s, flight),
                BatchSize::SmallInput,
            )
        },
    );

    group.bench_with_input(
        BenchmarkId::new("H3", 2_500_000),
        &sendbuf,
        |b, sendbuf| {
            b.iter_batched_ref(
                || {
                    // init called for each run
                    let mut s = Session::with_configs(&mut config_v1, &h3_config)
                        .unwrap();
                    s.handshake().unwrap();
                    let mut response_map = StreamIdHashMap::default();
                    let resp = vec![
                        Header::new(b":status", b"200"),
                        Header::new(b"server", b"quiche-test"),
                        Header::new(b"content-length", b"31250"),
                    ];
                    for _ in 0..NUMBER_OF_REQUESTS {
                        let (stream_id, _) = s.send_request(true).unwrap();
                        response_map.insert(stream_id, Vec::<u8>::new());
                        s.poll_server().unwrap(); // headers
                        s.poll_server().unwrap(); // finished event
                    }
                    for stream_id in response_map.keys() {
                        s.server
                            .send_response(
                                &mut s.pipe.server,
                                *stream_id,
                                &resp,
                                false,
                            )
                            .unwrap();
                        s.server
                            .send_body(
                                &mut s.pipe.server,
                                *stream_id,
                                &sendbuf,
                                true,
                            )
                            .unwrap();
                    }
                    // let's catch flying packets
                    let flight =
                        quiche::testing::emit_flight(&mut s.pipe.server).unwrap();
                    (s, flight, response_map)
                },
                |(ref mut s, flight, response_map)| {
                    bench_h3(s, flight, response_map)
                },
                BatchSize::SmallInput,
            )
        },
    );
    group.finish();
}

criterion_group! {
    name = h3_quicv1_vs_h3_quicv3;
    config = Criterion::default()
        .measurement_time(std::time::Duration::from_secs(1))
        .with_measurement(CPUTime)
        .sample_size(5000);
    targets = criterion_benchmark
}

criterion_main!(h3_quicv1_vs_h3_quicv3);
