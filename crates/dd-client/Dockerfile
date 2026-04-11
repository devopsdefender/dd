# dd-client — in-enclave agent web UI. Runs inside an easyenclave-
# sealed TDX VM as a workload alongside whatever the VM is hosting
# (e.g. openclaw, a worker workload). Talks to the local
# /var/lib/easyenclave/agent.sock and serves a browser UI + terminal.
#
# Build context MUST be the repo root (workspace). The
# push-management-images workflow sets context: . and
# file: crates/dd-client/Dockerfile.

FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p dd-client

# Runtime: debian-slim + cloudflared. dd-client receives a tunnel
# token from dd-register during Noise-XX handshake and spawns
# cloudflared as a subprocess to serve its web UI publicly.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && curl -fsSL -o /usr/local/bin/cloudflared \
        https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
    && chmod +x /usr/local/bin/cloudflared \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/dd-client /usr/local/bin/dd-client
ENTRYPOINT ["/usr/local/bin/dd-client"]
