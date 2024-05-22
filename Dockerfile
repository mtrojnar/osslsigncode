# Stage 1: Build osslsigncode on Alpine
FROM alpine:latest AS builder

# Install build dependencies
RUN apk add --no-cache build-base cmake openssl-dev zlib-dev

# Copy osslsigncode source code into the image
COPY . /source

# Build osslsigncode
RUN cd /source && \
    mkdir -p build && \
    cd build && \
    rm -f CMakeCache.txt && \
    cmake -S .. && \
    cmake --build . && \
    cmake --install .

# Stage 2: Create final image without build environment
FROM alpine:latest

# Copy compiled binary from builder stage
COPY --from=builder /usr/local/bin/osslsigncode /usr/local/bin/osslsigncode

# Install necessary runtime libraries (latest version)
RUN apk add --no-cache libcrypto3

# Set working directory
WORKDIR /workdir

# Declare volume to mount files
VOLUME [ "/workdir" ]
