#!/bin/sh -e

# Load Cargo environment if needed
which cargo >/dev/null || . "$HOME/.cargo/env"

make
cd bin/
./rtc_data_service
