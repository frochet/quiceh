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
use quiceh::BufFactory;
use quiceh::BufSplit;

const MAX_DATAGRAM_SIZE: usize = 1350;

fn bench_stream_send(pipe: &mut Pipe, sendbuf: &[u8], outbuf: &mut [u8]) {
    pipe.client.stream_send(4, sendbuf, true).unwrap();
    let (write, send_info) =
        pipe.client.send_on_path(outbuf, None, None).unwrap();
    black_box(outbuf);
    black_box(write);
    black_box(send_info);
}

fn bench_stream_send_zc<F: BufFactory<Buf = BenchBuf>>(
    pipe: &mut Pipe<F>, outbuf: &mut [u8],
) where
    <F as BufFactory>::Buf: BufSplit,
{
    let sendbuf: Vec<u8> = Vec::with_capacity(10000);
    pipe.client
        .stream_send_zc(
            4,
            BenchBufFactory::buf_from_slice(&sendbuf),
            Some(10000),
            true,
        )
        .unwrap();
    let (write, send_info) =
        pipe.client.send_on_path(outbuf, None, None).unwrap();
    black_box(outbuf);
    black_box(write);
    black_box(send_info);
}

fn criterion_benchmark(c: &mut Criterion<CPUTime>) {
    let mut config =
        quiceh::Config::new(quiceh::PROTOCOL_VERSION_VREVERSO).unwrap();
    config
        .set_application_protos(&[b"proto1", b"proto2"])
        .unwrap();
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

    let mut group = c.benchmark_group("send_path");
    let sendbuf = vec![0; 10000];
    group.throughput(Throughput::Bytes(10000));

    group.bench_with_input(
        BenchmarkId::new("send_path", 10000),
        &sendbuf,
        |b, sendbuf| {
            b.iter_batched_ref(
                || {
                    let mut pipe = Pipe::with_config(&mut config).unwrap();
                    let outbuf = vec![0; 65535];
                    pipe.handshake().unwrap();
                    (pipe, sendbuf, outbuf)
                },
                |(ref mut pipe, sendbuf, outbuf)| {
                    bench_stream_send(pipe, sendbuf, outbuf)
                },
                BatchSize::SmallInput,
            )
        },
    );

    group.bench_function(BenchmarkId::new("zerocopy_send_path", 10000), |b| {
        b.iter_batched_ref(
            || {
                let mut pipe =
                    Pipe::<BenchBufFactory>::with_config(&mut config).unwrap();
                let outbuf = vec![0; 65535];
                pipe.handshake().unwrap();
                (pipe, outbuf)
            },
            |(ref mut pipe, outbuf)| bench_stream_send_zc(pipe, outbuf),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

criterion_group! {
    name = send_cwin_bench;
    config = Criterion::default()
        .measurement_time(std::time::Duration::from_secs(1))
        .with_measurement(CPUTime)
        .sample_size(5000);
    targets = criterion_benchmark
}

criterion_main!(send_cwin_bench);
