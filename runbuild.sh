#!/bin/sh -e

# Load Cargo environment if needed
which cargo >/dev/null || . "$HOME/.cargo/env"

cargo build --release
cd rtc_data_enclave && make
