use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput,
BatchSize};

use cpu_time::ProcessTime;
use criterion::measurement::Measurement;
use criterion::measurement::ValueFormatter;
use quiche::testing::Pipe;
use std::time::Duration;

const NANOS_PER_SEC: u64 = 1_000_000_000;

pub struct CPUTime;
impl Measurement for CPUTime {
    type Intermediate = ProcessTime;
    type Value = Duration;

    fn start(&self) -> Self::Intermediate {
        ProcessTime::now()
    }

    fn end(&self, i: Self::Intermediate) -> Self::Value {
        i.elapsed()
    }

    fn add(&self, v1: &Self::Value, v2: &Self::Value) -> Self::Value {
        *v1 + *v2
    }

    fn zero(&self) -> Self::Value {
        Duration::from_secs(0)
    }

    fn to_f64(&self, val: &Self::Value) -> f64 {
        let nanos = val.as_secs() * NANOS_PER_SEC + u64::from(val.subsec_nanos());
        nanos as f64
    }

    fn formatter(&self) -> &dyn ValueFormatter {
        &DurationFormatter
    }
}


pub struct DurationFormatter;
impl DurationFormatter {
    fn bytes_per_second(&self, bytes: f64, typical: f64, values: &mut [f64]) -> &'static str {
        let bytes_per_second = bytes * (1e9 / typical);
        let (denominator, unit) = if bytes_per_second < 1024.0 {
            (1.0, "  B/s")
        } else if bytes_per_second < 1024.0 * 1024.0 {
            (1024.0, "KiB/s")
        } else if bytes_per_second < 1024.0 * 1024.0 * 1024.0 {
            (1024.0 * 1024.0, "MiB/s")
        } else {
            (1024.0 * 1024.0 * 1024.0, "GiB/s")
        };

        for val in values {
            let bytes_per_second = bytes * (1e9 / *val);
            *val = bytes_per_second / denominator;
        }

        unit
    }

    fn elements_per_second(&self, elems: f64, typical: f64, values: &mut [f64]) -> &'static str {
        let elems_per_second = elems * (1e9 / typical);
        let (denominator, unit) = if elems_per_second < 1000.0 {
            (1.0, " elem/s")
        } else if elems_per_second < 1000.0 * 1000.0 {
            (1000.0, "Kelem/s")
        } else if elems_per_second < 1000.0 * 1000.0 * 1000.0 {
            (1000.0 * 1000.0, "Melem/s")
        } else {
            (1000.0 * 1000.0 * 1000.0, "Gelem/s")
        };

        for val in values {
            let elems_per_second = elems * (1e9 / *val);
            *val = elems_per_second / denominator;
        }

        unit
    }
}

impl ValueFormatter for DurationFormatter {
    fn scale_values(&self, ns: f64, values: &mut [f64]) -> &'static str {
        let (factor, unit) = if ns < 10f64.powi(0) {
            (10f64.powi(3), "ps")
        } else if ns < 10f64.powi(3) {
            (10f64.powi(0), "ns")
        } else if ns < 10f64.powi(6) {
            (10f64.powi(-3), "us")
        } else if ns < 10f64.powi(9) {
            (10f64.powi(-6), "ms")
        } else {
            (10f64.powi(-9), "s")
        };

        for val in values {
            *val *= factor;
        }

        unit
    }

    fn scale_throughputs(
        &self, typical: f64, throughput: &Throughput, values: &mut [f64],
    ) -> &'static str {
        match *throughput {
            Throughput::Bytes(bytes) => self.bytes_per_second(bytes as f64, typical, values),
            Throughput::Elements(elems) => self.elements_per_second(elems as f64, typical, values),
            Throughput::BytesDecimal(_) => todo!(),
        }
    }

    fn scale_for_machines(&self, _values: &mut [f64]) -> &'static str {
        // no scaling is needed
        "ns"
    }
}

fn bench_v1_receive(pipe: &mut Pipe, flight: &mut Vec<(Vec<u8>, quiche::SendInfo)>, buf: &mut [u8]) {
    for &mut (ref mut pkt, ref mut si) in flight.iter_mut(){
        let info = quiche::RecvInfo {
            to: si.to,
            from: si.from,
        };
        pipe.client.recv(pkt, &mut pipe.client_app_buffers, info).unwrap();
    }
    let (_, _) = pipe.client.stream_recv(1, buf).unwrap();

    black_box(buf);
}

fn bench_v3_receive(pipe: &mut Pipe, flight: &mut Vec<(Vec<u8>, quiche::SendInfo)>) {
    for &mut (ref mut pkt, ref mut si) in flight.iter_mut() {
        let info = quiche::RecvInfo {
            to: si.to,
            from: si.from,
        };
        pipe.client.recv(pkt, &mut pipe.client_app_buffers, info).unwrap();
    }
    let (b, _, _) = pipe.client.stream_recv_v3(1, &mut pipe.client_app_buffers).unwrap();

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

    // We only Micro-benchmark processing the QUIC packets and emitting them to the application
    // through the stream_recv() call in V1 or the stream_recv_v3() call in V3.
    // We do this for a full cwnd.
    group.bench_with_input(BenchmarkId::new("Quic_V3_Recv_Path", 10000), &sendbuf,
        |b, sendbuf| {
            b.iter_batched_ref( || {
                let mut pipe_v3 = Pipe::with_config(&mut config_v3).unwrap();
                pipe_v3.handshake().unwrap();
                // designed to avoid having the receiver's buffer being initialized as
                // part of the benchmark.
                pipe_v3.server.stream_send(1, b"init", false).unwrap();
                pipe_v3.advance().unwrap();
                pipe_v3.client.stream_recv_v3(1, &mut pipe_v3.client_app_buffers).unwrap();
                pipe_v3.client.stream_consumed(1, 4, &mut pipe_v3.client_app_buffers).unwrap();
                pipe_v3.server.stream_send(1, sendbuf, false).unwrap();
                let flight = quiche::testing::emit_flight(&mut pipe_v3.server).unwrap();
                (pipe_v3, flight)
            },
            |(ref mut pipe, flight)| {
                bench_v3_receive(pipe, flight)
            },
            BatchSize::SmallInput,
            )
        });
    group.bench_with_input(BenchmarkId::new("Quic_V1_Recv_path", 10000), &sendbuf,
        |b, sendbuf| {
            //recv buffer initialization
            let mut buf = vec![0; 32768];
            b.iter_batched_ref( || {
                let mut pipe_v1 = Pipe::with_config(&mut config_v1).unwrap();
                pipe_v1.handshake().unwrap();
                pipe_v1.server.stream_send(1, sendbuf, false).unwrap();
                let flight = quiche::testing::emit_flight(&mut pipe_v1.server).unwrap();
                (pipe_v1, flight)
            },
            |(ref mut pipe, flight)| {
                bench_v1_receive(pipe, flight, &mut buf)
            },
            BatchSize::SmallInput,
            )
        });
    group.finish();
}

criterion_group!{
    name = benches;
    config = Criterion::default()
        //.with_profiler(PProfProfiler::new(100, Output::Flamegraph(None)))
        .measurement_time(std::time::Duration::from_secs(1))
        .with_measurement(CPUTime)
        .sample_size(5000);
    targets = criterion_benchmark
}
criterion_main!(benches);
