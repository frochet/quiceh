#![no_main]

#[macro_use]
extern crate libfuzzer_sys;

#[macro_use]
extern crate lazy_static;

use std::net::SocketAddr;

use std::sync::Mutex;
use std::sync::Once;

lazy_static! {
    static ref CONFIG: Mutex<quiceh::Config> = {
        let mut config = quiceh::Config::new(quiceh::PROTOCOL_VERSION).unwrap();
        config
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .unwrap();
        config.set_initial_max_data(30);
        config.set_initial_max_stream_data_bidi_local(15);
        config.set_initial_max_stream_data_bidi_remote(15);
        config.set_initial_max_stream_data_uni(10);
        config.set_initial_max_streams_bidi(3);
        config.set_initial_max_streams_uni(3);
        config.verify_peer(false);

        config.discover_pmtu(true);
        config.enable_early_data();
        config.enable_hystart(true);

        Mutex::new(config)
    };
}

static SCID: quiceh::ConnectionId<'static> =
    quiceh::ConnectionId::from_ref(&[0; quiceh::MAX_CONN_ID_LEN]);

static LOG_INIT: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    let from: SocketAddr = "127.0.0.1:1234".parse().unwrap();
    let to: SocketAddr = "127.0.0.1:4321".parse().unwrap();

    LOG_INIT.call_once(|| env_logger::builder().format_timestamp_nanos().init());

    let mut buf = data.to_vec();

    let mut conn = quiceh::connect(
        Some("quic.tech"),
        &SCID,
        to,
        from,
        &mut CONFIG.lock().unwrap(),
    )
    .unwrap();

    let info = quiceh::RecvInfo { from, to };

    conn.recv(&mut buf, info).ok();

    let mut out_buf = [0; 1500];
    while conn.send(&mut out_buf).is_ok() {}
});
