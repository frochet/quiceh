FROM rustlang/rust:nightly as fuzz

WORKDIR /build

COPY Cargo.toml Cargo.toml
COPY Makefile Makefile
COPY apps/ ./apps/
COPY fuzz/ ./fuzz/
COPY octets_rev/ ./octets_rev/
COPY qlog/ ./qlog/
COPY quiceh/ ./quiceh/

RUN apt-get update && apt-get install -y cmake && rm -rf /var/lib/apt/lists/*

RUN cargo install cargo-fuzz
RUN make build-fuzz

##
## quiceh-libfuzzer: quiceh image for fuzzing
##
FROM debian:latest as quiceh-libfuzzer

LABEL maintainer="alessandro@cloudflare.com"

WORKDIR /home/mayhem/

RUN apt-get update && apt-get install -y ca-certificates llvm && rm -rf /var/lib/apt/lists/*

COPY fuzz/cert.crt ./
COPY fuzz/cert.key ./

COPY --from=fuzz \
     /build/fuzz/target/x86_64-unknown-linux-gnu/release/packet_recv_client \
     /build/fuzz/target/x86_64-unknown-linux-gnu/release/packet_recv_server \
     /build/fuzz/target/x86_64-unknown-linux-gnu/release/qpack_decode \
     ./
