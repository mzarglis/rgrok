# Build stage
FROM rust:1.88-bookworm AS builder

WORKDIR /build
COPY . .
RUN cargo build --release --bin rgrok-server

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

RUN useradd --system --create-home --shell /usr/sbin/nologin rgrok \
    && mkdir -p /etc/rgrok /var/lib/rgrok/certs \
    && chown -R rgrok:rgrok /var/lib/rgrok

COPY --from=builder /build/target/release/rgrok-server /usr/local/bin/rgrok-server
COPY deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0555 /usr/local/bin/docker-entrypoint.sh

USER rgrok

# Control plane, HTTP, HTTPS
EXPOSE 7835 80 443
# TCP tunnel port range
EXPOSE 10000-20000

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--config", "/etc/rgrok/server.toml"]
