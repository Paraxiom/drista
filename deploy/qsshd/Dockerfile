# Build qsshd and qssh-keygen from the QSSH source tree
# Usage: docker build -t qsshd -f deploy/qsshd/Dockerfile /path/to/qssh

FROM rust:1.75-slim AS builder
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release --bin qsshd --bin qssh-keygen

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/qsshd /usr/local/bin/
COPY --from=builder /build/target/release/qssh-keygen /usr/local/bin/
EXPOSE 4242
ENTRYPOINT ["qsshd"]
CMD ["--listen", "0.0.0.0:4242"]
