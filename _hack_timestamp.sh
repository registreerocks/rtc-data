#!/bin/sh -e

# See all.sh
#
# This works around cargo rebuilding sgx_unwind unnecessarily due to config.h.in* churn.
# Run this before (and/or after) each relevant cargo invocation.

# See "Pinning SGX dependencies" in HACKING.md.
# This revision should match the Rust SGX SDK revision we're pinned to.
base='/root/.cargo/git/checkouts/incubator-teaclave-sgx-sdk-c63c8825343e87f0/b9d1bda/sgx_unwind/libunwind'

if test -e "$base"; then
  touch --reference "$base/configure.in" "$base/include/config.h.in" "$base/include/config.h.in~"
else
  echo "$0: warning: missing $base"
fi
