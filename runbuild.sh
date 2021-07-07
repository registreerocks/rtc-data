#!/bin/sh -e

# Load Cargo environment if needed
which cargo >/dev/null || . "$HOME/.cargo/env"

cargo build --release
cd rtc_data_enclave && make && cd ..
cd rtc_auth_enclave && make && cd ..
cd rtc_exec_enclave && make && cd ..
