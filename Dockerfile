# Use Debian Bookworm (32-bit) ARM base image for Raspberry Pi
# Using balenalib which has excellent ARM6L support for Raspberry Pi Zero/1
FROM balenalib/raspberry-pi:bookworm-build

# Install Rust (build-essential and pkg-config already included in balenalib build image)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

# Set working directory
WORKDIR /app

# Copy the project files
COPY Cargo.toml Cargo.lock ./
COPY src ./src

# Build the relay binary in release mode
RUN cargo build --release --bin relay

# The binary will be available at /app/target/release/relay
CMD ["/app/target/release/relay"]
