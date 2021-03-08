FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive
ENV rust_toolchain  nightly-2020-10-25
ENV sdk_bin         https://download.01.org/intel-sgx/sgx-linux/2.9.1/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.9.101.2.bin

RUN apt-get update && \
    apt-get install -y gnupg2 apt-transport-https ca-certificates curl software-properties-common build-essential automake autoconf libtool protobuf-compiler libprotobuf-dev git-core libprotobuf-c0-dev cmake pkg-config expect gdb libssl-dev

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

# Setup the rust toolchain for building
RUN curl 'https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init' --output /root/rustup-init && \
    chmod +x /root/rustup-init && \
    echo '1' | /root/rustup-init --default-toolchain ${rust_toolchain} && \
    echo 'source /root/.cargo/env' >> /root/.bashrc && \
    /root/.cargo/bin/rustup component add rust-src rls rust-analysis clippy rustfmt && \
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

# Donwload the teaclave rust sgx sdk
RUN mkdir /root/sgx-rust && \
    curl -L https://github.com/apache/incubator-teaclave-sgx-sdk/archive/v1.1.3.tar.gz | tar -xz -C /root/sgx-rust --strip-components=1

WORKDIR /root
