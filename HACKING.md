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


## Aligned memory allocation for secret values

In enclave code, all memory allocations for sensitive secret values (such as cryptographic keys)
must be padded and aligned to protect against certain cache timing side-channel attacks,
as detailed in the Intel's INTEL-SA-00219  Developer Guidance.

The Rust SGX SDK [provides primitives] (`AlignBox` and `sgx_align_*`) to help implement this guidance,
but other enclave secrets must also be allocated similarly.

[provides primitives]: https://github.com/apache/incubator-teaclave-sgx-sdk/wiki/Mitigation-of-Intel-SA-00219-in-Rust-SGX#rust-sgx-provided-primitive

In particular, care must be taken to allocate aligned memory _before_ initialising secrets in it,
rather than initialising secrets in unaligned memory and then moving them to aligned memory.

In this codebase, also see the `AlignedKey` type in the `rtc_tenclave::dh::types` module.

Background:

* [CVE-2019-0117](http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-0117)
* [Intel SGX SDK Developer Guidance INTEL-SA-00219](https://software.intel.com/content/www/us/en/develop/download/intel-sgx-sdk-developer-guidance-intel-sa-00219.html)
  ([PDF](https://software.intel.com/content/dam/develop/public/us/en/documents/intel-sgx-sdk-developer-guidance-intel-sa-00219.pdf))


Rust SGX SDK:

* [v1.1.0 release notes](https://github.com/apache/incubator-teaclave-sgx-sdk/blob/v1.1.0/release_notes.md#rust-sgx-sdk-v110)
* [Mitigation of Intel SA 00219 in Rust SGX](https://github.com/apache/incubator-teaclave-sgx-sdk/wiki/Mitigation-of-Intel-SA-00219-in-Rust-SGX)

