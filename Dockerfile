# devopsdefender — unified binary for fleet management.
#
# DEVELOPMENT ONLY. CI/CD does not use this — easyenclave fetches the
# devopsdefender binary directly from this repo's GitHub releases via
# its github_release workload source. See .github/workflows/release.yml.
# This Dockerfile is kept for local development and ad-hoc image builds.
#
# Subcommands:
#   devopsdefender management  — control plane (register + dashboard)
#   devopsdefender agent       — in-VM agent

FROM rust:1-bookworm AS builder
RUN rustup target add x86_64-unknown-linux-musl && \
    apt-get update && apt-get install -y --no-install-recommends musl-tools && \
    rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cargo build --release -p devopsdefender --target x86_64-unknown-linux-musl

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates curl \
    && curl -fsSL -o /usr/local/bin/cloudflared \
        https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
    && chmod +x /usr/local/bin/cloudflared \
    && apt-get purge -y curl \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/x86_64-unknown-linux-musl/release/devopsdefender /usr/local/bin/devopsdefender
ENTRYPOINT ["/usr/local/bin/devopsdefender"]
