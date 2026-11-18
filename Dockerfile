# syntax=docker/dockerfile:1

# Builder: edition 2024 needs stable >= 1.85; mimalloc and zstd-sys need a C
# toolchain. musl matches the Alpine runtime base (a glibc-linked binary would
# not exec there). Cargo.lock is copied for a reproducible --locked build;
# migrations are a compile-time input of sqlx::migrate! (src/lib.rs).
FROM rust:alpine AS builder

RUN apk add --no-cache \
        build-base \
        musl-dev \
        pkgconfig \
        cmake \
        perl \
        ca-certificates

WORKDIR /app
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
COPY src ./src
RUN cargo build --release --locked --bin cardinal

# Runtime: PostgreSQL 18 + TimescaleDB and the official postgres entrypoint
# (initdb / POSTGRES_USER / POSTGRES_DB / POSTGRES_PASSWORD) come from the base
# image (Alpine; gosu and pg_isready are already present). Cardinal is the only
# extra process, and PostgreSQL listens on loopback only, so no database port
# is published.
FROM timescale/timescaledb:latest-pg18

RUN apk add --no-cache \
        bash \
        curl \
        ca-certificates \
        tzdata \
        tini \
    && mkdir -p /data/home \
    && addgroup -g 10001 -S cardinal \
    && adduser -u 10001 -G cardinal -h /data/home -s /sbin/nologin -S -D cardinal

COPY --from=builder /app/target/release/cardinal /usr/local/bin/cardinal
COPY docker/entrypoint.sh /usr/local/bin/cardinal-entrypoint.sh
RUN chmod 0755 /usr/local/bin/cardinal-entrypoint.sh

ENV HOME=/data/home \
    PGDATA=/data/pgdata \
    TZ=UTC \
    POSTGRES_USER=cardinal \
    POSTGRES_DB=cardinal

VOLUME /data
EXPOSE 8787
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=10s --timeout=5s --start-period=30s --retries=6 \
    CMD curl -fsS http://127.0.0.1:8787/health || exit 1

ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/cardinal-entrypoint.sh"]
