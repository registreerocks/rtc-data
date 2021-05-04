#syntax=docker/dockerfile:1.2

# Base with APT packages installed
FROM ubuntu:18.04 AS apt-base

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y gnupg2 apt-transport-https ca-certificates curl software-properties-common build-essential automake autoconf libtool protobuf-compiler libprotobuf-dev git-core libprotobuf-c0-dev cmake pkg-config expect gdb libssl-dev llvm-dev libclang-dev clang && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/apt/archives/*

#  Add SGX repository and install SGX libraries
RUN curl -fsSL https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | apt-key add - && \
    add-apt-repository "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu bionic main" && \
    apt-get update  && \
    apt-get install -y libsgx-quote-ex \
        libsgx-enclave-common libsgx-enclave-common-dev \
        libsgx-dcap-ql libsgx-dcap-ql-dev && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/apt/archives/* && \
    mkdir /var/run/aesmd && \
    mkdir /etc/init

# Add Microsoft's repository and install Azure libraries
RUN curl -fsSL  https://packages.microsoft.com/keys/microsoft.asc | apt-key add - && \
    add-apt-repository "deb [arch=amd64] https://packages.microsoft.com/ubuntu/18.04/prod bionic main" && \
    apt-get update  && \
    apt-get install -y az-dcap-client && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf /var/cache/apt/archives/*


# Base with the SGX and Teaclave SDKs installed
FROM apt-base AS teaclave-base

# See:
# https://github.com/apache/incubator-teaclave-sgx-sdk/blob/master/release_notes.md
# https://01.org/intel-software-guard-extensions/downloads
ARG rust_toolchain=nightly-2020-10-25
ARG sdk_bin=https://download.01.org/intel-sgx/sgx-linux/2.13/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.13.100.4.bin
ARG teaclave_version=1.1.3

# Setup the rust toolchain for building
RUN curl 'https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init' --output /root/rustup-init && \
    chmod +x /root/rustup-init

RUN echo '1' | /root/rustup-init --default-toolchain ${rust_toolchain}

RUN echo 'source /root/.cargo/env' >> /root/.bashrc

RUN /root/.cargo/bin/rustup component add rust-src rls rust-analysis clippy rustfmt && \
    rm /root/rustup-init && rm -rf /root/.cargo/registry && rm -rf /root/.cargo/git

# Install the sgx sdk
RUN mkdir /root/sgx && \
    curl --output /root/sgx/sdk.bin ${sdk_bin} && \
    cd /root/sgx && \
    chmod +x /root/sgx/sdk.bin && \
    echo -e 'no\n/opt' | /root/sgx/sdk.bin && \
    # echo 'source /opt/sgxsdk/environment' >> /root/.bashrc && \
    echo 'alias start-aesm="LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm /opt/intel/sgx-aesm-service/aesm/aesm_service"' >> /root/.bashrc && \
    rm -rf /root/sgx*

# Download the teaclave rust sgx sdk
RUN mkdir /root/sgx-rust && \
    curl -L https://github.com/apache/incubator-teaclave-sgx-sdk/archive/v${teaclave_version}.tar.gz | tar -xz -C /root/sgx-rust --strip-components=1

# TODO: remove once all the code supports the later nightly toolchains
RUN /root/.cargo/bin/rustup toolchain install nightly-2021-03-25

FROM teaclave-base AS builder
ENV SGX_SDK=/opt/sgxsdk
WORKDIR /root

COPY --from=teaclave-base /root/sgx-rust/ ./sgx-rust/
COPY --from=teaclave-base /root/.cargo/ ./.cargo/

WORKDIR /root/rtc-data
ARG SGX_MODE=HW

COPY . .
RUN --mount=type=cache,target=/root/.cargo/registry \
    --mount=type=cache,target=/root/.cargo/git \
    --mount=type=cache,sharing=private,target=/root/rtc-data/target \
    --mount=type=cache,sharing=private,target=/root/rtc-data/rtc_data_enclave/target \
    ./runbuild.sh && \
    mkdir /root/out && \
    cp target/release/http_server /root/out/http_server

FROM teaclave-base AS runsw

WORKDIR /root/rtc-data
COPY --from=builder /root/rtc-data/rtc_data_service/http_server/config ./config
COPY --from=builder /root/out/http_server ./http_server
COPY --from=builder /root/rtc-data/rtc_data_enclave/build/bin/enclave.signed.so ./enclave.signed.so

EXPOSE 8080

CMD ["./http_server"]

FROM apt-base AS runhw

WORKDIR /root/rtc-data
COPY --from=builder /root/rtc-data/rtc_data_service/http_server/config ./config
COPY --from=builder /root/out/http_server ./http_server
COPY --from=builder /root/rtc-data/rtc_data_enclave/build/bin/enclave.signed.so ./enclave.signed.so

EXPOSE 8080

CMD ["./http_server"]
