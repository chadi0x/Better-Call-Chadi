# Build stage
FROM rust:latest as builder

WORKDIR /usr/src/app
COPY . .
RUN cargo install --path .

# Runtime stage
FROM debian:bookworm-slim
COPY --from=builder /usr/local/cargo/bin/chadi_rust /usr/local/bin/chadi_rust
CMD ["chadi_rust"]
