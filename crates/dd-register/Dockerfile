# dd-register — tunnel provisioning service. Runs inside an
# easyenclave-sealed TDX VM as a boot workload.
#
# Build context MUST be the repo root (workspace root) so that the
# dd-common path dep resolves. The push-management-images workflow
# sets context: . and file: crates/dd-register/Dockerfile.

FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p dd-register

# Runtime: debian-slim + cloudflared. dd-register spawns cloudflared
# as a subprocess (via dd-common::tunnel) to run the tunnel it
# provisions through the Cloudflare API.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && curl -fsSL -o /usr/local/bin/cloudflared \
        https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
    && chmod +x /usr/local/bin/cloudflared \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/dd-register /usr/local/bin/dd-register
ENTRYPOINT ["/usr/local/bin/dd-register"]
