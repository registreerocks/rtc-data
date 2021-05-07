#!/bin/sh -ex
# This will run the tests in all of the needed directories
cargo test -- --nocapture

# The rtc_tenclave tests require --no-default-features to run.
(cd rtc_tenclave && cargo test --no-default-features)
