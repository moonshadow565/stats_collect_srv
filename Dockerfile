FROM ekidd/rust-musl-builder:1.57.0 AS chef
# Install cargo tool used for caching
RUN cargo install cargo-chef
# Set working directory for our app
WORKDIR /stats_collect_srv

FROM chef AS planner
# Copy over the Cargo.toml and Cargo.lock files
COPY ./Cargo.* ./
# Copy over the source files
COPY ./src ./src
# Create a recipe for our app thats used for caching
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
# Copy over the recipe we created
COPY --from=planner /stats_collect_srv/recipe.json recipe.json
# Build the dependencies specified in the recipe we created so they can be cached
RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json
# Copy everthing over
COPY . .
# Run normal cargo build
RUN cargo build --release --target x86_64-unknown-linux-musl

FROM alpine AS runtime
# Set app working directory
WORKDIR /stats_collect_srv
# Copy the binary to the working directory
COPY --from=builder /stats_collect_srv/target/x86_64-unknown-linux-musl/release/stats_collect_srv ./

# Set default environment variables
ENV SRV_HOST=0.0.0.0 \
    SRV_PORT=8080 \
    SRV_TIMEOUT_ADD=1 \
    SRV_AUTH_LIST= \
    SRV_FILENAME=/data/entries.csv \
    RUST_LOG=info \
    RUST_BACKTRACE=1

# Expose port to host
EXPOSE ${SRV_PORT}

# Check if our app is running as intended 
HEALTHCHECK --interval=5m --timeout=3s \
  CMD wget --no-verbose --tries=1 --spider http://${SRV_HOST}:${SRV_PORT} || exit 1

# Run app
CMD ["/stats_collect_srv/stats_collect_srv"]