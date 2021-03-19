# Base with APT packages installed
FROM ubuntu:18.04 AS apt-base

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y gnupg2 apt-transport-https ca-certificates curl software-properties-common build-essential automake autoconf libtool protobuf-compiler libprotobuf-dev git-core libprotobuf-c0-dev cmake pkg-config expect gdb libssl-dev && \
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
FROM apt-base AS user-base
ARG UID=1000
RUN useradd --create-home --shell /bin/bash --uid "${UID}" dev
USER dev
WORKDIR /home/dev

# Base with the SGX and Teaclave SDKs installed
FROM user-base AS teaclave-base

# See:
# https://github.com/apache/incubator-teaclave-sgx-sdk/blob/master/release_notes.md
# https://01.org/intel-software-guard-extensions/downloads
ARG rust_toolchain=nightly-2020-10-25
ARG sdk_bin=https://download.01.org/intel-sgx/sgx-linux/2.13/distro/ubuntu18.04-server/sgx_linux_x64_sdk_2.13.100.4.bin
ARG teaclave_version=1.1.3

# Setup the rust toolchain for building
RUN curl 'https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init' --output $HOME/rustup-init && \
    chmod +x $HOME/rustup-init && \
    echo '1' | $HOME/rustup-init --default-toolchain ${rust_toolchain} && \
    echo 'source $HOME/.cargo/env' >> $HOME/.bashrc && \
    $HOME/.cargo/bin/rustup component add rust-src rls rust-analysis clippy rustfmt && \
    rm $HOME/rustup-init && rm -rf $HOME/.cargo/registry && rm -rf $HOME/.cargo/git

# Install the sgx sdk
RUN mkdir $HOME/sgx && \
    curl --output $HOME/sgx/sdk.bin ${sdk_bin} && \
    cd $HOME/sgx && \
    chmod +x $HOME/sgx/sdk.bin && \
    echo -e 'no\n$HOME/opt' | $HOME/sgx/sdk.bin && \
    # echo 'source $HOME/opt/sgxsdk/environment' >> $HOME/.bashrc && \
    echo 'alias start-aesm="LD_LIBRARY_PATH=/opt/intel/sgx-aesm-service/aesm /opt/intel/sgx-aesm-service/aesm/aesm_service"' >> $HOME/.bashrc && \
    rm -rf $HOME/sgx*

# Download the teaclave rust sgx sdk
RUN mkdir $HOME/sgx-rust && \
    curl -L https://github.com/apache/incubator-teaclave-sgx-sdk/archive/v${teaclave_version}.tar.gz | tar -xz -C $HOME/sgx-rust --strip-components=1
