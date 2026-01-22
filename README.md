![quiceh](quiceh.png)

quiceh is a research implementation of QUIC VReverso, an extension of
the QUIC transport protocol which allows implementers to achieve higher
efficiency through the new opportunity to implement contiguous zero-copy
of arbitrary size in the receive code path without touching the Crypto backend, which is
otherwise impossible with QUIC version 1 (RFC9000). This research
implementation is forked from Cloudflare's
[quiche](https://github.com/cloudflare/quiche) implementation of the
QUIC transport protocol. This repository is not aimed to compete with
the original implementation, which is qualitative and should be used
rather than this project. This repository serves as reference
implementation for academic research. However, interested Application
developers are welcome to try it and offer feedbacks. 

Details on why/how QUIC VReverso implementations are expected to be more
efficient than QUIC V1 implementations can be read on the blogpost which
we made available through QUIC V1 and QUIC VReverso.  

[https://reverso.info.unamur.be](https://reverso.info.unamur.be)

Even more details are availbale in the academic paper, on .pdf:

[Reverso paper](https://dl.acm.org/doi/epdf/10.1145/3787927.3787929)

The most desirable outcome is that this proposal eventually makes it to
the official QUIC design, and QUIC implementations eventually take
advantage of the new efficiency possibilities. You're most welcome to
show support to this proposal in any way you feel is suitable. Thanks!

Efficiency improvement
----------------------

- VReverso reports an improvement of ~30% over the receive code path using
[`stream_peek()`] and [`stream_consumed()`] compared to QUIC V1. This is
currently the default contiguous zero-copy interaction being used in apps/ and
implemented in the HTTP/3 module. This is the main research
contribution requiring an adaptation of QUIC's wire image, and only
available if the connection negotiates protocol version 0x00791097. Note
that this improvement depends on the library architecture and API
choice. Other QUIC implementations may obtain lower or higher
improvement depending on their software architecture choice, but some
improvement should be expected in all cases.

- [`stream_recv_zc()`] only available for VReverso supports the
Application to receive contiguous chunks of memory from underlying
quiceh buffers in contiguous zero-copy in expectation. This is designed for
concurrent processing of stream data. By default, chunks are 64KiB,
and can be configured using the connection [`Config`]'s
[`set_expected_chunklen_to_consume()`] call. [`stream_recv_zc()`] can be used
together with [`stream_peek()`] and [`stream_consumed()`], although
received chunks are considered as consumed from the internal QUIC recv
stream buffer. Dropping the chunk sends the memory allocation back to
the stream buffer pool.

- Support sending in zero-copy for both QUIC v1 and QUIC VReverso using
  [`stream_send_zc()`]. Current server behavior implemented in apps/ for
sending HTTP/3 responses.

Experimental:

- QUIC connection [`Config`] may set a flag using
  [`enable_hidden_copy_for_zc_sender()`] to make any data buffered
through either [`stream_send()`] or [`stream_send_zc()`] assembled in
zero-copy in a QUIC packet using BoringSSL's scatter encryption. This
has a currently limited performance improvement for large blobs of data
and much lower performance for sending small blobs of data.

Using quiceh 
------------

### Overview of the main differences with [quiche](https://github.com/cloudflare/quiche)

quiceh has a few API extensions, and any application using
[quiche](https://github.com/cloudflare/quiche) would have to slightly
change its code to hopefully benefits from the optimizations. Of course,
these optimizations only work if the Application negotiates QUIC
VReverso with the peer.

```rust let mut config =
quiceh::Config::new(quiceh::PROTOCOL_VERSION_VREVERSO)?;
```

Using `PROTOCOL_VERSION_VREVERSO` which currently holds the temporary
value 0x00791097 would make your endpoint tries to negotiate VReverso
first, and fallback to QUIC V1 if not available.
Client side or server side, the
[quiche](https://github.com/cloudflare/quiche) API to initiate a
connection stays the same:

```rust
// Client connection.
let conn = quiceh::connect(Some(&server_name), &scid, local, peer, &mut config)?;

// Server connection.
let conn = quiceh::accept(&scid, None, local, peer, &mut config)?;
```

We have slight differences in processing packets and reading data
from a stream. quiceh exposes new APIs to read/process bytes in
zero-copy. Here's an example using [`stream_peek()`] and
[`stream_consumed()`].

```rust
let to = socket.local_addr().unwrap();

loop {
    let (len, from) = match socket.recv_from(&mut buf) {
        Ok(v) => v,

        Err(e) => {
            // There are no more UDP packets to read, so end the read
            // loop.
            if e.kind() == std::io::ErrorKind::WouldBlock {
                debug!("recv() would block");
                break;
            }

            panic!("recv() failed: {:?}", e);
        },
    };

    // One may either continue to drain the socket, or directly pass
    // the data to quiceh, as done here.

    let recv_info = quiceh::RecvInfo { from, to };

    let read = match conn.recv(&mut buf[..read], recv_info) {
        Ok(v) => v,

        Err(e) => {
            // An error occurred, handle it.
            break;
        },
    };
}

// The application can check whether there are any readable streams by using
// the connection's [`readable()`] method, which returns an iterator over all
// the streams that have outstanding data to read.

if conn.is_established() {
    // Iterate over readable streams.
    for stream_id in conn.readable() {
        // Stream is readable, get a reference to the internal
        // contiguous stream data
        let (streambuf, len, fin) = conn.stream_peek(stream_id).unwrap();

        // ... do something with streambuf

        // Optionally mark some data consumed to release it.
        // If this function is not called, then the next stream_peek
        // Would point to the same bytes, + any new content appended up
        // the stream's maximum window.

        conn.stream_consumed(stream_id, len).unwrap();
    }
}
```

Alternatively, if the Application requires ownership of the stream
bytes:

```rust

if conn.is_established() {
    // Iterate over readable streams.
    for stream_id in conn.readable() {
        // By default, chunks are 64 KiB buffers, this function will
        // return it if it is full or if the fin bit is true  
        // 
        // If one wants to read/consume partially from the incomplete
        // chunk, stream_peek() and stream_consume() are available.
        while let Ok((chunk, fin)) = conn.stream_recv_zc(stream_id) {
            println!("Got {} bytes on stream {}", chunk.len(),
            stream_id);
        }
    }
}

```

### Command-line apps

Here are a few examples on how to use the quiceh tools provided as part
of the [quiceh-apps](apps/) crate. This crate is an extension of the
[quiche-apps](https://github.com/cloudflare/quiche/tree/master/apps)
crate, supporting both QUIC VReverso and QUIC V1, as well as adding
recvmmsg() on the client and sendmmsg() on the server using the
[quinn-udp](https://github.com/quinn-rs/quinn/tree/main/quinn-udp)
crate.

After cloning the project according to the command mentioned in the
[building](#building) section, the client can be run as follows:

```bash
 $ cargo run --bin quiceh-client -- --wire-version 00791097 -- https://reverso.info.unamur.be:4433
```

Using `--wire-version 00791097` configures PROTOCOL_VERSION_VREVERSO.
If you want QUIC V1, you may use 00000001.

```bash
 $ cargo run --bin quiceh-server -- --cert apps/src/bin/cert.crt --key apps/src/bin/cert.key --root .
```

(note that the certificate provided is self-signed and should not be used in
production).

Use the `--help` command-line flag to get a more detailed description of each
tool's options. If you'd like to make a straightforward test on the
loopback address, the following should work from the root of the
repository (after `cargo build --release`):

```bash
$ ./target/release/quiceh-server --key apps/src/bin/cert.key --cert apps/src/bin/cert.crt --root .
```

And using the client client to fetch the readme, with some logging
enabled on on stdout should print the README.md file on stdout with some
logging information for the connection:

```bash
$ RUST_LOG=info ./target/release/quiceh-client --wire-version 00791097 --no-verify https://127.0.0.1:4433/README.md
... <skip readme file>
[2024-05-02T11:44:40.893910677Z INFO  quiceh_apps::client] connecting to 127.0.0.1:4433 from 0.0.0.0:49803 with scid 97dcac3544c9e1f0d7a9d3e562c8e6c3e5bd03f9
[2024-05-02T11:44:40.907967338Z INFO  quiceh_apps::common] 1/1 response(s) received in 13.94742ms, closing...
[2024-05-02T11:44:40.919080924Z INFO  quiceh_apps::client] connection closed, recv=18 sent=11 lost=0 retrans=0 sent_bytes=2409 recv_bytes=15345 lost_bytes=0 [local_addr=0.0.0.0:49803 peer_addr=127.0.0.1:4433 validation_state=Validated active=true recv=18 sent=11 lost=0 retrans=0 rtt=1.325962ms min_rtt=Some(1.070281ms) rttvar=583.985µs cwnd=13500 sent_bytes=2409 recv_bytes=15345 lost_bytes=0 stream_retrans_bytes=0 pmtu=1350 delivery_rate=1328623]
```

### Advanced Configurations

The [`Config`] object controls important aspects of the QUIC connection such
as QUIC version, ALPN IDs, flow control, congestion control, idle timeout
and other properties or features.

QUIC is a general-purpose transport protocol and there are several
configuration properties where there is no reasonable default value. For
example, the permitted number of concurrent streams of any particular type
is dependent on the application running over QUIC, and other use-case
specific concerns.

quiceh defaults several properties to zero, applications most likely need
to set these to something else to satisfy their needs using the following:

- [`set_initial_max_streams_bidi()`]
- [`set_initial_max_streams_uni()`]
- [`set_initial_max_data()`]
- [`set_initial_max_stream_data_bidi_local()`]
- [`set_initial_max_stream_data_bidi_remote()`]
- [`set_initial_max_stream_data_uni()`]

[`Config`] also holds TLS configuration. This can be changed by mutators on
the existing object, or by constructing a TLS context manually and
creating a configuration using [`with_boring_ssl_ctx_builder()`].

A configuration object can be shared among multiple connections.

Applications should use [`set_expected_chunklen_to_consume()`] of
[`Config`] to set the typical length it expects to consume at once. This
value influences the size of the chunks being returned by
[`stream_recv_zc()`] while processing stream data. Setting a size below
a typical QUIC Stream frame length may lower performance compared to
QUIC v1 and is unadvised. The default is currently 64KiB.

### Generating outgoing packets

This aspect of [quiche](https://github.com/cloudflare/quiche) is
untouched at the API level. Outgoing packet are generated using the
connection's [`send()`] method:

```rust
loop {
    let (write, send_info) = match conn.send(&mut out) {
        Ok(v) => v,

        Err(quiceh::Error::Done) => {
            // Done writing.
            break;
        },

        Err(e) => {
            // An error occurred, handle it.
            break;
        },
    };

    socket.send_to(&out[..write], &send_info.to).unwrap();
}
```

When packets are sent, the application is responsible for maintaining a
timer to react to time-based connection events. The timer expiration can be
obtained using the connection's [`timeout()`] method.

```rust
let timeout = conn.timeout();
```

The application is responsible for providing a timer implementation, which
can be specific to the operating system or networking framework used. When
a timer expires, the connection's [`on_timeout()`] method should be called,
after which additional packets might need to be sent on the network:

```rust
// Timeout expired, handle it.
conn.on_timeout();

// Send more packets as needed after timeout.
loop {
    let (write, send_info) = match conn.send(&mut out) {
        Ok(v) => v,

        Err(quiceh::Error::Done) => {
            // Done writing.
            break;
        },

        Err(e) => {
            // An error occurred, handle it.
            break;
        },
    };

    socket.send_to(&out[..write], &send_info.to).unwrap();
}
```

#### Pacing

It is recommended that applications [pace] sending of outgoing packets to
avoid creating packet bursts that could cause short-term congestion and
losses in the network.

quiceh exposes pacing hints for outgoing packets through the [`at`] field
of the [`SendInfo`] structure that is returned by the [`send()`] method.
This field represents the time when a specific packet should be sent into
the network.

Applications can use these hints by artificially delaying the sending of
packets through platform-specific mechanisms (such as the [`SO_TXTIME`]
socket option on Linux), or custom methods (for example by using user-space
timers).

[pace]: https://datatracker.ietf.org/doc/html/rfc9002#section-7.7
[`SO_TXTIME`]: https://man7.org/linux/man-pages/man8/tc-etf.8.html

#### Sending stream data

After some back and forth, the connection will complete its handshake and
will be ready for sending or receiving application data.

Data can be sent on a stream by using either the [`stream_send()`]
method or the [`stream_send_zc()`] method for zero-copy:

```rust
if conn.is_established() {
    // Handshake completed, send some data on stream 4.
    conn.stream_send(4, b"hello", true)?;
}
```

In the case of zero-copy, the application must use an object
implementing the trait BufFactory provided by quiceh.

```rust
/// A trait for providing internal storage buffers for [`RangeBuf`].
/// The associated type `Buf` can be any type that dereferences to
/// a slice, but should be fast to clone, eg. by wrapping it with an
/// [`Arc`].
pub trait BufFactory: Clone + Default + Debug {
    /// The type of the generated buffer.
    type Buf: Clone + Debug + AsRef<[u8]>;

    /// Generate a new buffer from a given slice, the buffer must contain the
    /// same data as the original slice.
    fn buf_from_slice(buf: &[u8]) -> Self::Buf;
}
```

The generated buffer Buf must implement the trait BufSplit:

```rust
/// A trait that enables zero-copy sends to quiceh. When buffers produced
/// by the `BufFactory` implement this trait, quiceh and h3 can supply the
/// raw buffers to be sent, instead of slices that must be copied first.
pub trait BufSplit {
    /// Split the buffer at a given point, after the split the old buffer
    /// must only contain the first `at` bytes, while the newly produced
    /// buffer must containt the remaining bytes.
    fn split_at(&mut self, at: usize) -> Self;
}
```

Assuming MyBuf implements BufFactory, we can send in zero-copy:

```rust
if conn.is_established() {
    // Handshake completed, send some data on stream 4.
    conn.stream_send_zc(4, MyBuf::buf_from_slice(b"hello"), Some(5), true)?;
}
```

An example is available in apps/src/common.rs

### HTTP/3

The quiceh [HTTP/3 module] provides a high level API for sending and
receiving HTTP requests and responses on top of the QUIC transport protocol.

Have a look at the [quiceh/examples/] directory for more complete examples on
how to use the quiceh API.

The apps/ directory contains a more complete implementation of a HTTP/3
client/server using the zero-copy HTTP/3 module.

The main differences with
[quiche](https://github.com/cloudflare/quiche)'s HTTP/3 module are the
use of [`poll_v3()`] replacing [`poll()`], [`body_peek()`] replacing
[`recv_body()`] and the addition of [`body_consumed()`] to tell HTTP/3
how much of the data frame has been consumed (up to the announced max
value that [`body_peek()`] announces.  Pretty much all the rest remains
the same.

[examples/]: quiceh/examples/


Building
--------

quiceh requires Rust 1.79 or later to build. The latest stable Rust release can
be installed using [rustup](https://rustup.rs/).

Once the Rust build environment is setup, the quiceh source code can be fetched
using git:

```bash
 $ git clone --recursive git@github.com:frochet/quiceh
```

and then built using cargo:

```bash
 $ cargo build --examples
```

cargo can also be used to run the testsuite:

```bas
 $ cargo test
```

Note that [BoringSSL], which is used to implement QUIC's cryptographic handshake
based on TLS, needs to be built and linked to quiceh. This is done automatically
when building quiceh using cargo, but requires the `cmake` command to be
available during the build process. On Windows you also need
[NASM](https://www.nasm.us/). The [official BoringSSL
documentation](https://github.com/google/boringssl/blob/master/BUILDING.md) has
more details.

```bash
 $ QUICEH_BSSL_PATH="/path/to/boringssl" cargo build --examples
```
[BoringSSL]: https://boringssl.googlesource.com/boringssl/

Research
--------

- Commit "Towards Protocol Reverso" contains an example of
required work to support QUIC VReverso. It adds support for backwards
processing, for writing and parsing frames in the "reversed" order, and
unit tests for all QUIC features with these changes. 

- Commit "starting the work on Zerocopy receiver" contains an example of
  implementation taking advantage of the new protocol specification to
  support contiguous zero-copy.  

These two commits on the top of
[quiche](https://github.com/cloudflare/quiche) make up quiceh.  

If you use this code in your research, please cite the following paper:  

[Reverso](https://dl.acm.org/doi/epdf/10.1145/3787927.3787929) 

@article{10.1145/3787927.3787929,
    author = {Rochet, Florentin},
    title = {Contiguous Zero-Copy for Encrypted Transport Protocols},
    year = {2026},
    issue_date = {July 2025},
    publisher = {Association for Computing Machinery},
    address = {New York, NY, USA},
    volume = {55},
    number = {3},
    issn = {0146-4833},
    url = {https://doi.org/10.1145/3787927.3787929},
    doi = {10.1145/3787927.3787929},
    abstract = {We propose in this paper to revisit the design of existing encrypted transport protocols to improve their efficiency. We call the methodology "Reverso" from reversing the order of field elements within a protocol specification. We detail how such a benign-looking change within the specifications may unlock contiguous zero-copy for encrypted protocols during data transport. To demonstrate our findings, we release quiceh, a QUIC implementation of QUIC VReverso, an extension of the QUIC V1 standard (RFC9000). Our methodology applied to the QUIC protocol reports ≈ 30\% of CPU efficiency improvement for processing packets at no added cost on the sender side and without relaxing any security guarantee from QUIC V1. We also implement a fork of Cloudflare's HTTP/3 module and client/server demonstrator using quiceh and show our optimizations to directly transfer to HTTP/3 as well, resulting in our new HTTP/3 to be ≈ 38\% more efficient than the baseline implementation using QUIC V1. We argue that Reverso applies to any modern encrypted protocol and its implementations and that similar efficiency improvement can also be unlocked for them, independently of the layer in which they operate. Indeed, this research shows that the ability to implement contiguous zero-copy on the receiver side inherently depends on the specified encrypted protocol wire image, and that we may need to reverse how we are used to write them.},
    journal = {SIGCOMM Comput. Commun. Rev.},
    month = jan,
    pages = {2–18},
    numpages = {17},
    keywords = {security and privacy, network security, security protocols}
}

You may also cite this repository separately:  

@misc{frochet-quiceh,  
&nbsp;&nbsp;title={quiceh: an implementation of QUIC VReverso},  
&nbsp;&nbsp;author={Florentin Rochet},  
&nbsp;&nbsp;howpublished={\url{https://github.com/frochet/quiceh}}  
}


Copyright
---------

Copyright (C) 2018-2019, Cloudflare, Inc.

See [COPYING] for the license.

[COPYING]: https://github.com/frochet/quiceh/tree/protocol_reverso/COPYING

[`Config`]: https://docs.rs/quiceh/latest/quiceh/struct.Config.html
[`recv`]: https://docs.rs/quiceh/latest/quiceh/struct.Connection.html#method.recv
[`enable_hidden_copy_for_zc_sender()`]: https://docs.rs/quiceh/latest/quiceh/struct.Config.html#method.enable_hidden_copy_for_zc_sender
[`stream_peek()`]: https://docs.rs/quiceh/latest/quiceh/struct.Connection.html#method.stream_peek
[`stream_recv_zc()`]: https://docs.rs/quiceh/latest/quiceh/struct.Connection.html#method.stream_recv_zc
[`stream_consumed()`]: https://docs.rs/quiceh/latest/quiceh/struct.Connection.html#method.stream_consumed
[`set_initial_max_streams_bidi()`]: https://docs.rs/quiceh/latest/quiceh/struct.Config.html#method.set_initial_max_streams_bidi
[`set_initial_max_streams_uni()`]: https://docs.rs/quiceh/latest/quiceh/struct.Config.html#method.set_initial_max_streams_uni
[`set_initial_max_data()`]: https://docs.rs/quiceh/latest/quiceh/struct.Config.html#method.set_initial_max_data
[`set_initial_max_stream_data_bidi_local()`]: https://docs.rs/quiceh/latest/quiceh/struct.Config.html#method.set_initial_max_stream_data_bidi_local
[`set_initial_max_stream_data_bidi_remote()`]: https://docs.rs/quiceh/latest/quiceh/struct.Config.html#method.set_initial_max_stream_data_bidi_remote
[`set_initial_max_stream_data_uni()`]: https://docs.rs/quiceh/latest/quiceh/struct.Config.html#method.set_initial_max_stream_data_uni
[`set_expected_chunklen_to_consume()`]: https://docs.rs/quiceh/latest/quiceh/struct.Config.html#method.set_expected_chunklen_to_consume
[`with_boring_ssl_ctx_builder()`]: https://docs.rs/quiceh/latest/quiceh/struct.Config.html#method.with_boring_ssl_ctx_builder
[`send()`]: https://docs.rs/quiceh/latest/quiceh/struct.Connection.html#method.send
[`timeout()`]: https://docs.rs/quiceh/latest/quiceh/struct.Connection.html#method.timeout
[`on_timeout()`]: https://docs.rs/quiceh/latest/quiceh/struct.Connection.html#method.on_timeout
[`SendInfo`]: https://docs.rs/quiceh/latest/quiceh/struct.SendInfo.html
[`at`]: https://docs.rs/quiceh/latest/quiceh/struct.SendInfo.html#structfield.at
[`stream_send()`]: https://docs.rs/quiceh/latest/quiceh/struct.Connection.html#method.steam_send
[`stream_send_zc()`]: https://docs.rs/quiceh/latest/quiceh/struct.Connection.html#method.steam_send_zc
