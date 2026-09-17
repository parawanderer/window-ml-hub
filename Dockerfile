# The window.ml hub. Build: docker build -t wmlhub .   Run: see compose.yaml and docs/SELF_HOSTING.md.

# ---- build ----
FROM rust:1.98.1-slim-bookworm AS build
WORKDIR /src
# rust-toolchain.toml pins the same compiler this image ships, so nothing is downloaded here.
COPY . .
RUN cargo build --release --locked -p wmlhub && cp target/release/wmlhub /usr/local/bin/wmlhub

# ---- run ----
FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin wmlhub \
    && mkdir -p /data && chown wmlhub /data
COPY --from=build /usr/local/bin/wmlhub /usr/local/bin/wmlhub
USER wmlhub
# Accounts and invites live here; mount a volume so they survive a rebuild.
VOLUME /data
ENV WMLHUB_LISTEN=0.0.0.0:8787 \
    WMLHUB_STATE_DIR=/data \
    WMLHUB_REGISTRATION=invite
EXPOSE 8787
ENTRYPOINT ["wmlhub"]
CMD ["serve"]
