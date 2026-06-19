# syntax=docker/dockerfile:1.7
# vault42-server production image. Multi-stage: build the gRPC binary with the pinned
# Rust toolchain (protoc is vendored by the proto build script — no system protoc), then
# ship it on distroless. The image carries ONLY the binary; sealed state lives on a
# mounted encrypted volume at /data. TLS is terminated at the fly edge (plaintext h2c here).

FROM public.ecr.aws/docker/library/rust:1.96-slim-bookworm AS builder
RUN apt-get update \
 && apt-get install -y --no-install-recommends pkg-config \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release --bin vault42-server \
 && cp target/release/vault42-server /vault42-server

# distroless/cc carries glibc + CA roots (for the optional grobase TLS hop) and no shell.
FROM gcr.io/distroless/cc-debian12 AS runtime
COPY --from=builder /vault42-server /vault42-server
ENV VAULT42_HOST=0.0.0.0 \
    VAULT42_PORT=8443 \
    VAULT42_DB=/data/vault42.db \
    RUST_LOG=info
EXPOSE 8443
ENTRYPOINT ["/vault42-server"]
