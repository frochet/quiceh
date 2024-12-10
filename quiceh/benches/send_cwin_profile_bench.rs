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
use pprof::criterion::{PProfProfiler, Output};

const MAX_DATAGRAM_SIZE: usize = 1350;


// /!\ this code is designed for flamegraph inspection of the send path logic; not to get reliable
// efficiency measurements.
fn bench_stream_send(pipe: &mut Pipe, config: &mut quiceh::Config, outbuf: &mut [u8], sendbuf: &[u8], stream_id: &mut u64) {
    // Every 1000 iteration we destroy the pipe. Otherwise we have memory issues since it send may
    // grow the pipe's mem. We don't re-do an handshake at each sample bench outside of the timed
    // function, or the flamegraph would be unreadable.
    if *stream_id > 1_000 {
        std::mem::swap(pipe, &mut Pipe::with_config(config).unwrap());
        pipe.handshake().unwrap();
        *stream_id = 0;
    }
    *stream_id += 4;
    pipe.client.stream_send(*stream_id, sendbuf, true).unwrap();

    loop {
        let (write, send_info) = match pipe.client.send_on_path(outbuf, None, None) {
            Ok(v) => v,

            Err(quiceh::Error::Done) => {
                // we sent everything
                break;
            },

            Err(e) => {
                panic!("An error occured {:?}", e);
            }
        };
        black_box(write);
        black_box(send_info);
    }
    black_box(outbuf);
}

fn bench_stream_send_zc<F: BufFactory<Buf = BenchBuf>>(
    pipe: &mut Pipe<F>, config: &mut quiceh::Config, outbuf: &mut [u8], benchbuf: &F::Buf, stream_id: &mut u64,
) where
    <F as BufFactory>::Buf: BufSplit,
{
    if *stream_id > 1_000 {
        std::mem::swap(pipe, &mut Pipe::with_config(config).unwrap());
        pipe.handshake().unwrap();
        *stream_id = 0;
    }
    *stream_id += 4;
    pipe.client
        .stream_send_zc(
            *stream_id,
            benchbuf.clone(),
            Some(10000),
            true,
        )
        .unwrap();
    loop {
        let (write, send_info) = match pipe.client.send_on_path(outbuf, None, None) {
            Ok(v) => v,

            Err(quiceh::Error::Done) => {
                break;
            },

            Err(e) => {
                panic!("An error occured {:?}", e);
            }
        };
        black_box(write);
        black_box(send_info);
    }
    black_box(outbuf);
}

fn bench_sender(c: &mut Criterion<CPUTime>, config: &mut quiceh::Config, name: &str) {
    let mut group = c.benchmark_group(name);
    group.throughput(Throughput::Bytes(10000));

    let mut pipe = Pipe::with_config(config).unwrap();
    pipe.handshake().unwrap();
    let sendbuf = vec![0; 10000];
    let mut stream_id = 0;
    group.bench_with_input(
        BenchmarkId::new("send_path", 10000),
        &sendbuf,
        |b, sendbuf| {
            b.iter_batched_ref(
                || {
                    let outbuf = vec![0; 65535];
                    outbuf
                },
                |ref mut outbuf| {
                    bench_stream_send(&mut pipe, config, outbuf, sendbuf, &mut stream_id)
                },
                BatchSize::SmallInput,
            );
        },
    );

    let benchbuf = BenchBufFactory::buf_from_slice(&sendbuf);
    let mut pipe =
        Pipe::<BenchBufFactory>::with_config(config).unwrap();
    pipe.handshake().unwrap();
    stream_id = 0;

    group.bench_with_input(
        BenchmarkId::new("zerocopy_send_path", 10000),
        &benchbuf,
        |b, benchbuf| {
        b.iter_batched_ref(
            || {
                let outbuf = vec![0; 65535];
                outbuf
            },
            |ref mut outbuf| bench_stream_send_zc(&mut pipe, config, outbuf, benchbuf, &mut stream_id),
            BatchSize::SmallInput,
        )
    });

    group.finish();
}

fn send_bench_hidden_copy(c: &mut Criterion<CPUTime>) {
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
    config.set_initial_congestion_window_packets(20_000_000);
    config.verify_peer(false);
    config.enable_pacing(false);
    config.enable_hidden_copy_for_zc_sender(true);

    bench_sender(c, &mut config, "send_path_with_hidden_copy");

}

fn send_bench_no_hidden_copy(c: &mut Criterion<CPUTime>) {
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
    config.set_initial_congestion_window_packets(20_000_000);
    config.verify_peer(false);
    config.enable_pacing(false);
    config.enable_hidden_copy_for_zc_sender(false);

    bench_sender(c, &mut config, "send_path_no_hidden_copy");

}

criterion_group! {
    name = send_cwin_profile_bench;
    config = Criterion::default()
        .measurement_time(std::time::Duration::from_millis(1000))
        .with_profiler({
            let mut options = pprof::flamegraph::Options::default();
            options.image_width = Some(10000);
            PProfProfiler::new(999, Output::Flamegraph(Some(options)))
        })
        .with_measurement(CPUTime)
        .sample_size(5000);
    targets = send_bench_no_hidden_copy, send_bench_hidden_copy
}

criterion_main!(send_cwin_profile_bench);
