# dd-web — fleet dashboard, auth, collector. Runs inside an
# easyenclave-sealed TDX VM as a boot workload alongside dd-register.
#
# Build context MUST be the repo root. The push-management-images
# workflow sets context: . and file: crates/dd-web/Dockerfile.

FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p dd-web

# Runtime: plain debian-slim. No cloudflared — dd-web doesn't create
# tunnels (that's dd-register's job). dd-web talks to the local
# easyenclave socket and to GitHub / Cloudflare HTTPS APIs, so
# ca-certificates is all we need beyond the binary itself.
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/release/dd-web /usr/local/bin/dd-web
ENTRYPOINT ["/usr/local/bin/dd-web"]
