mod bench_util;
use bench_util::*;
use criterion::black_box;
use criterion::criterion_group;
use criterion::criterion_main;
use criterion::BatchSize;
use criterion::BenchmarkId;
use criterion::Criterion;
use criterion::Throughput;
use quiceh::testing::Pipe;
use quiceh::StreamChunk;
use std::env;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

const MAX_DATAGRAM_SIZE: usize = 1350;

/// Bench reception, reallocation and dropping of chunks
///
/// Reallocation may happen within recv()
fn bench_stream_recv_zc(
    pipe: &mut Pipe, flight: &mut Vec<(Vec<u8>, quiceh::SendInfo)>,
    tx: &mut Sender<StreamChunk>,
) {
    let mut flight_iter_mut = flight.iter_mut();
    while let Some(&mut (ref mut pkt, ref mut si)) = flight_iter_mut.next() {
        let info = quiceh::RecvInfo {
            to: si.to,
            from: si.from,
        };
        pipe.client
            .recv(pkt, &mut pipe.client_app_buffers, info)
            .unwrap();
        if let Ok((chunk, _)) =
            pipe.client.stream_recv_zc(1, &mut pipe.client_app_buffers)
        {
            // Chunk is handled and dropped through another thread.
            tx.send(chunk).unwrap();
        }
    }
}

fn criterion_benchmark(c: &mut Criterion<CPUTime>) {
    let mut config =
        quiceh::Config::new(quiceh::PROTOCOL_VERSION_VREVERSO).unwrap();

    config
        .load_cert_chain_from_pem_file("examples/cert.crt")
        .unwrap();
    config
        .load_priv_key_from_pem_file("examples/cert.key")
        .unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000_000);
    config.set_max_stream_window(25_165_824);
    config.set_initial_max_stream_data_uni(10_000_000_000);
    config.set_initial_max_streams_bidi(10_000_000_000);
    config.set_initial_max_stream_data_bidi_local(10_000_000_000);
    config.set_initial_max_stream_data_bidi_remote(10_000_000_000);
    config.verify_peer(false);

    let mut group = c.benchmark_group("stream_recv_zc");
    // Use an environement variable to control the buffer size since
    // Criterion does not support command line arguments.
    let sendbuf_size: usize = env::var("SENDBUF_SIZE")
        .ok()
        .and_then(|size| size.parse::<usize>().ok())
        .unwrap_or(64 * 1024);
    let chunklen: usize = env::var("CHUNK_SIZE")
        .ok()
        .and_then(|size| size.parse::<usize>().ok())
        .unwrap_or(5000);

    let sendbuf = vec![0; sendbuf_size];
    // Make sure we can send the whole buffer at once.
    config.set_initial_congestion_window_packets(
        (sendbuf_size as f64 / MAX_DATAGRAM_SIZE as f64).ceil() as usize,
    );
    group.throughput(Throughput::Bytes(sendbuf_size as u64));

    group.bench_with_input(
        BenchmarkId::new("send_recv_zc", sendbuf_size),
        &sendbuf,
        |b, sendbuf| {
            b.iter_batched_ref(
                || {
                    let mut pipe = Pipe::with_config(&mut config).unwrap();
                    let (tx, rx): (Sender<StreamChunk>, Receiver<StreamChunk>) =
                        mpsc::channel();
                    let handle = thread::spawn(move || {
                        while let Ok(chunk) = rx.recv() {
                            black_box(chunk);
                        }
                    });
                    pipe.handshake().unwrap();
                    pipe.set_client_expected_chunklen_to_consume(chunklen);
                    pipe.server.stream_send(1, sendbuf, true).unwrap();
                    let flights =
                        quiceh::testing::emit_flight(&mut pipe.server).unwrap();
                    (pipe, flights, handle, tx)
                },
                |(ref mut pipe, flight, _handle, tx)| {
                    bench_stream_recv_zc(pipe, flight, tx)
                },
                BatchSize::SmallInput,
            )
        },
    );
}

criterion_group! {
    name = stream_recv_zc;
    config = Criterion::default()
        .measurement_time(std::time::Duration::from_secs(10))
        .with_measurement(CPUTime)
        .sample_size(5000);
    targets = criterion_benchmark
}

criterion_main!(stream_recv_zc);
