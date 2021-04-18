#!/bin/sh -e
# This will run the tests in all of the needed directories
cargo test -Zextra-link-arg -- --nocapture
