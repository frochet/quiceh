mod bench_util;
use bench_util::*;
use criterion::black_box;
use criterion::criterion_group;
use criterion::criterion_main;
use criterion::BatchSize;
use criterion::BenchmarkId;
use criterion::Criterion;
use criterion::Throughput;
use quiche::testing::Pipe;

fn bench_v1_receive(
    pipe: &mut Pipe, flight: &mut Vec<(Vec<u8>, quiche::SendInfo)>,
    buf: &mut [u8],
) {
    for &mut (ref mut pkt, ref mut si) in flight.iter_mut() {
        let info = quiche::RecvInfo {
            to: si.to,
            from: si.from,
        };
        pipe.client
            .recv(pkt, &mut pipe.client_app_buffers, info)
            .unwrap();
    }
    let (..) = pipe.client.stream_recv(1, buf).unwrap();

    black_box(buf);
}

fn bench_v3_receive(
    pipe: &mut Pipe, flight: &mut Vec<(Vec<u8>, quiche::SendInfo)>,
) {
    for &mut (ref mut pkt, ref mut si) in flight.iter_mut() {
        let info = quiche::RecvInfo {
            to: si.to,
            from: si.from,
        };
        pipe.client
            .recv(pkt, &mut pipe.client_app_buffers, info)
            .unwrap();
    }
    let (b, ..) = pipe
        .client
        .stream_recv_v3(1, &mut pipe.client_app_buffers)
        .unwrap();

    black_box(b);
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
    config_v1.set_initial_max_data(10_000_000_000);
    config_v1.set_max_stream_window(25_165_824);
    config_v1.set_initial_max_stream_data_uni(10_000_000_000);
    config_v1.set_initial_max_streams_bidi(10_000_000_000);
    config_v1.set_initial_max_stream_data_bidi_local(10_000_000_000);
    config_v1.set_initial_max_stream_data_bidi_remote(10_000_000_000);
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
    config_v3.set_initial_max_data(10_000_000_000);
    config_v3.set_max_stream_window(25_165_824);
    config_v3.set_initial_max_stream_data_uni(10_000_000_000);
    config_v3.set_initial_max_streams_bidi(10_000_000_000);
    config_v3.set_initial_max_stream_data_bidi_local(10_000_000_000);
    config_v3.set_initial_max_stream_data_bidi_remote(10_000_000_000);
    config_v3.verify_peer(false);

    let mut group = c.benchmark_group("Quiche_Recv_path");
    let sendbuf = vec![0; 10000];
    group.throughput(Throughput::Bytes(10000));

    // We only Micro-benchmark processing the QUIC packets and emitting them to
    // the application through the stream_recv() call in V1 or the
    // stream_recv_v3() call in V3. We do this for a full cwnd.
    group.bench_with_input(
        BenchmarkId::new("Quic_V3_Recv_Path", 10000),
        &sendbuf,
        |b, sendbuf| {
            b.iter_batched_ref(
                || {
                    let mut pipe_v3 = Pipe::with_config(&mut config_v3).unwrap();
                    pipe_v3.handshake().unwrap();
                    // designed to avoid having the receiver's buffer being
                    // initialized as part of the benchmark.
                    pipe_v3.server.stream_send(1, b"init", false).unwrap();
                    pipe_v3.advance().unwrap();
                    pipe_v3
                        .client
                        .stream_recv_v3(1, &mut pipe_v3.client_app_buffers)
                        .unwrap();
                    pipe_v3
                        .client
                        .stream_consumed(1, 4, &mut pipe_v3.client_app_buffers)
                        .unwrap();
                    pipe_v3.server.stream_send(1, sendbuf, false).unwrap();
                    let flight =
                        quiche::testing::emit_flight(&mut pipe_v3.server)
                            .unwrap();
                    (pipe_v3, flight)
                },
                |(ref mut pipe, flight)| bench_v3_receive(pipe, flight),
                BatchSize::SmallInput,
            )
        },
    );
    group.bench_with_input(
        BenchmarkId::new("Quic_V1_Recv_path", 10000),
        &sendbuf,
        |b, sendbuf| {
            // recv buffer initialization
            let mut buf = vec![0; 32768];
            b.iter_batched_ref(
                || {
                    let mut pipe_v1 = Pipe::with_config(&mut config_v1).unwrap();
                    pipe_v1.handshake().unwrap();
                    pipe_v1.server.stream_send(1, sendbuf, false).unwrap();
                    let flight =
                        quiche::testing::emit_flight(&mut pipe_v1.server)
                            .unwrap();
                    (pipe_v1, flight)
                },
                |(ref mut pipe, flight)| bench_v1_receive(pipe, flight, &mut buf),
                BatchSize::SmallInput,
            )
        },
    );
    group.finish();
}

criterion_group! {
    name = quicv1_vs_quicv3_cwin;
    config = Criterion::default()
        //.with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)))
        .measurement_time(std::time::Duration::from_secs(1))
        .with_measurement(CPUTime)
        .sample_size(5000);
    targets = criterion_benchmark
}

criterion_main!(quicv1_vs_quicv3_cwin);
