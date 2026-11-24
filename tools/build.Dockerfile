# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Ottenheimer GmbH
#
# Build environment for the corpus: every toolchain the six projects'
# proofstein.json files declare, in one image, so tools/build-all.sh runs as
# written on any host with Docker. See METHODOLOGY.md §8, step 4.
#
#   docker build -t proofstein-build -f tools/build.Dockerfile tools
#   docker run --rm -u "$(id -u):$(id -g)" -v "$PWD":/work -v <build-root>:/build \
#       -e HOME=/build/home -e PROOFSTEIN_BUILD_ROOT=/build -w /work \
#       proofstein-build tools/build-all.sh [ground-truth-holdout]
#
# The base image is pinned by digest and the JDK by release and SHA-256. The
# Debian packages are whatever trixie carries on the day the image is built;
# build-all.sh prints each toolchain's version, and a run records them.

# debian:trixie, resolved 2026-11-24
FROM debian@sha256:3cda3ca472ce45507a5109c6a3907093e24d9ae67d55954c9a07a45665dafba2

# C: OpenSSL 3.5 (tinyattest's ML-KEM and X25519MLKEM768), autotools for the
# wolfSSL source build, mingw-w64 for tinyattest's Windows CNG file.
# Go 1.24 (beacon-relay), Rust (sealbox), Node 20 (session-broker), Maven
# (ledger-svc), Python 3 with venv and a compiler (vaultkeeper's liboqs-python).
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential pkg-config libssl-dev openssl autoconf automake libtool \
      gcc-mingw-w64-x86-64 curl ca-certificates git cmake ninja-build \
      python3 python3-venv python3-pip python3-dev \
      nodejs npm maven golang-go cargo rustc \
    && rm -rf /var/lib/apt/lists/*

# ledger-svc compiles for Java 21 and needs 24 or newer at run time for its
# ML-KEM path: Temurin 25.0.5.1+2.
ARG JDK_URL=https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.5.1%2B2/OpenJDK25U-jdk_x64_linux_hotspot_25.0.5.1_2.tar.gz
ARG JDK_SHA256=760f91b22c3efc9bd1b64ff950598231be82928cc807e30691a0e7a2995a62c0
RUN curl -fsSL "$JDK_URL" -o /opt/jdk.tar.gz \
    && echo "$JDK_SHA256  /opt/jdk.tar.gz" | sha256sum -c - \
    && mkdir /opt/jdk && tar -xzf /opt/jdk.tar.gz -C /opt/jdk --strip-components=1 \
    && rm /opt/jdk.tar.gz
ENV JAVA_HOME=/opt/jdk PATH=/opt/jdk/bin:$PATH
