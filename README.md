# RTC-Data
## Setting up rust
1. Install [rustup](https://rustup.rs/)
2. Set the default rust toolchain to the latest nightly supported by the [rust-sgx-sdk](https://github.com/apache/incubator-teaclave-sgx-sdk)

   Currently this is `nightly-2020-10-25`. So do `rustup default nightly-2020-10-25`
   
3. Install the relevant rust tooling for you IDE/Text editor
   - VSCode: [plugin on the marketplace](https://marketplace.visualstudio.com/items?itemName=rust-lang.rust)
     I would recommend using rust-analyzer rather than rls. Check the plugin settings for more info
   - Jetbrains: [Open source plugin for their IDEs](https://www.jetbrains.com/rust/)
   - Other: For any editor with support for the language server protocol, I would recommend using rust analyzer. See the editor's LSP docs for info on how to install
4. For debugging you can use gdb from the interactive shell of the docker environment

## SGX Setup
For a dev environment, SGX does not need to be setup on the host machine. All building will happen inside of the docker container, and simulation mode should be fine
for most cases. If you want to use the hardware capabilities you can install the SGX driver and pass through the device when starting the docker container.

## Running the dev container
Use `docker-compose run dev` to start the dev container. This will put you in an interactive shell.

To run the application inside of the container, do `cd rtc-data` and then `./runall.sh`

## Running tests

Helper script:

```shell
./runtests.sh
```

Currently, some tests with static mocks can intermittently fail due to test thread concurrency.
(For example, see test `rtc_enclave::tests::dcap_azure_attestation_works`.)

To avoid this, run:

```shell
cargo test -- --test-threads=1
```

or set:

```shell
export RUST_TEST_THREADS=1
```

TODO(Pi): We should probably configure single-threading by default in affected crates
once `cargo test` implements this:

* [Enable specifying --test-threads in Cargo.toml #8430](https://github.com/rust-lang/cargo/issues/8430)
