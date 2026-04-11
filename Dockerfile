FROM docker.io/library/rust:1-bookworm AS builder

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends clang pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY supplied ./supplied

RUN cargo build --locked --release -p pyregistry \
    && cp /app/target/release/pyregistry /usr/local/bin/pyregistry

FROM docker.io/library/debian:bookworm-slim AS runtime

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libgcc-s1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home-dir /var/lib/pyregistry --create-home pyregistry \
    && mkdir -p /var/lib/pyregistry/blobs /app/supplied \
    && chown -R pyregistry:pyregistry /var/lib/pyregistry /app

WORKDIR /app

COPY --from=builder /usr/local/bin/pyregistry /usr/local/bin/pyregistry
COPY --from=builder /app/supplied /app/supplied

ENV BIND_ADDRESS=0.0.0.0:3000 \
    BLOB_ROOT=/var/lib/pyregistry/blobs \
    DATABASE_STORE=sqlite \
    SQLITE_PATH=/var/lib/pyregistry/pyregistry.sqlite3 \
    ARTIFACT_STORAGE_BACKEND=opendal \
    OPENDAL_SCHEME=fs \
    OPENDAL_ROOT=/var/lib/pyregistry/blobs \
    YARA_RULES_PATH=/app/supplied/signature-base/yara

EXPOSE 3000

USER pyregistry

ENTRYPOINT ["pyregistry"]
CMD ["serve"]
