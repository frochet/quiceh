FROM rust:1.66 as build

WORKDIR /build

COPY apps/ ./apps/
COPY octets_rev/ ./octets_rev/
COPY qlog/ ./qlog/
COPY quiceh/ ./quiceh/

RUN apt-get update && apt-get install -y cmake && rm -rf /var/lib/apt/lists/*

RUN cargo build --manifest-path apps/Cargo.toml

##
## quiceh-base: quiceh image for apps
##
FROM debian:latest as quiceh-base

RUN apt-get update && apt-get install -y ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY --from=build \
     /build/apps/target/debug/quiceh-client \
     /build/apps/target/debug/quiceh-server \
     /usr/local/bin/

ENV PATH="/usr/local/bin/:${PATH}"
ENV RUST_LOG=info

##
## quiceh-qns: quiceh image for quic-interop-runner
## https://github.com/marten-seemann/quic-network-simulator
## https://github.com/marten-seemann/quic-interop-runner
##
FROM martenseemann/quic-network-simulator-endpoint:latest as quiceh-qns

WORKDIR /quiceh

COPY --from=build \
     /build/apps/target/debug/quiceh-client \
     /build/apps/target/debug/quiceh-server \
     /build/apps/run_endpoint.sh \
     ./

ENV RUST_LOG=trace

ENTRYPOINT [ "./run_endpoint.sh" ]
