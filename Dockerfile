# Build environment for pq-authd on Ubuntu 24.04
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Base build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        build-essential \
        cmake \
        git \
        pkg-config \
        libssl-dev \
        libkrb5-dev && \
    rm -rf /var/lib/apt/lists/*

# Build and install liboqs from source
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs && \
    cmake -S /tmp/liboqs -B /tmp/liboqs/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=ON && \
    cmake --build /tmp/liboqs/build --config Release && \
    cmake --install /tmp/liboqs/build && \
    rm -rf /tmp/liboqs

# Project source will be mounted at /src from the host
WORKDIR /src

# Default command is a shell; the build script will specify what to run
CMD ["bash"]
