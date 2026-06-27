# Multi-stage build for the Signet blind-signing service.
# Stage 1: build a static-ish release binary.
FROM rust:1.85-slim-bookworm AS builder

WORKDIR /build

# Cache dependencies first.
COPY Cargo.toml Cargo.lock ./
# A throwaway lib + bin so `cargo build` can resolve & compile deps before the
# real sources are copied (better layer caching).
RUN mkdir -p src \
    && echo "fn main() {}" > src/main.rs \
    && echo "" > src/lib.rs \
    && cargo build --release --bin signet 2>/dev/null || true

# Now copy the real sources and build for real.
COPY src ./src
COPY examples ./examples
# Touch to force a rebuild of our crate (deps stay cached).
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --bin signet \
    && cargo build --release --example gen_certs

# Stage 2: minimal runtime image.
FROM debian:bookworm-slim AS runtime

# Non-root user.
RUN useradd --system --uid 10001 --no-create-home signet \
    && mkdir -p /data /certs \
    && chown signet:signet /data

COPY --from=builder /build/target/release/signet /usr/local/bin/signet
COPY --from=builder /build/target/release/examples/gen_certs /usr/local/bin/signet-gen-certs

USER signet
WORKDIR /data

# The service listens on 8443 (mTLS). It is NOT published to the host in
# compose; only the internal network can reach it.
EXPOSE 8443

ENTRYPOINT ["/usr/local/bin/signet"]
