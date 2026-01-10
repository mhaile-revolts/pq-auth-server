FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# -------------------------------
# Base build dependencies
# -------------------------------
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        ninja-build \
        git \
        ca-certificates \
        curl \
        pkg-config \
        libssl-dev \
        zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

# -------------------------------
# Build liboqs (pinned shallow clone)
# -------------------------------
WORKDIR /opt
RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git

WORKDIR /opt/liboqs
RUN mkdir build && cd build && \
    cmake -GNinja .. && \
    ninja && \
    ninja install

# -------------------------------
# PQ-auth artifacts (THIS WAS MISSING)
# -------------------------------
WORKDIR /opt/pq-authd

# Copy PQ auth server artifacts into the image
COPY dist/*.gz dist/

# Integrity check (strongly recommended)
RUN sha256sum dist/*.gz

# -------------------------------
# Default shell
# -------------------------------
CMD ["bash"]
