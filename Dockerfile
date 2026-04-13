# dd — unified binary for DevOps Defender fleet management.
#
# Subcommands:
#   dd management  — control plane (dd-register + dd-web)
#   dd agent       — in-VM agent (dd-client)
#
# Build context MUST be the repo root (workspace root) so that
# path deps resolve. The push-management-images workflow sets
# context: . and file: Dockerfile.

FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p dd

# Runtime: debian-slim + cloudflared. Both `dd management` and
# `dd agent` spawn cloudflared as a subprocess for CF tunnels.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && curl -fsSL -o /usr/local/bin/cloudflared \
        https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
    && chmod +x /usr/local/bin/cloudflared \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/dd /usr/local/bin/dd
ENTRYPOINT ["/usr/local/bin/dd"]
