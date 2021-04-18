#!/bin/sh -e

# Load Cargo environment if needed
which cargo >/dev/null || . "$HOME/.cargo/env"

./runtests.sh
./runserver.sh
