# Working on this project

## Pinning SGX dependencies

We currently depend on a post-v1.1.3 revision of `sgx_types` for this PR,
which was merged in [b9d1bda](https://github.com/apache/incubator-teaclave-sgx-sdk/commit/b9d1bda674564668f8cf2e1ee202d08533fde46f):

* [feat(sgx_types): add traits using derive #325](https://github.com/apache/incubator-teaclave-sgx-sdk/pull/325)

Because of how Cargo resolves Git repository references, _all_ dependency references to the
`incubator-teaclave-sgx-sdk` repository should be qualified with this same revision,
to prevent Cargo from resolving conflicting versions of the SGX SDK packages:

```toml
sgx_tstd = { git = "https://github.com/apache/incubator-teaclave-sgx-sdk.git", rev = "b9d1bda" }
```

Note that most of the SGX packages still refer to the old `teaclave-sgx-sdk` repo,
so these references must be patched like this:

```toml
[patch."https://github.com/apache/teaclave-sgx-sdk.git"]
sgx_tstd = { git = "https://github.com/apache/incubator-teaclave-sgx-sdk.git", rev = "b9d1bda" }
```

However, also note that Cargo currently has this limitation:

* [Cannot patch underspecified git dependency #7670](https://github.com/rust-lang/cargo/issues/7670)

This prevents patching a repository reference to a different revision in the same repository,
which makes some SGX-patched packages (such as `serde-sgx` and `serde-json-sgx`) tricky to deal with.
