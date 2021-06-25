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

### Cargo patch limitation workaround

Ideally, we want to explicitly specify the tag or revision of the SGX-forked packages we use,
like this:

```toml
serde = { git = "https://github.com/mesalock-linux/serde-sgx", tag = "sgx_1.1.3" }
```

However, this fails for packages that are also listed as dependencies of other SGX-forked packages
_without_ the explicit tag: Cargo will resolve these as different crates, which causes problems
(such as different crates referring to different versions of `serde`'s traits).

We cannot use `[patch]` to override these dependencies to use the same specifiers,
because of this Cargo limitation:

* [Cannot patch underspecified git dependency #7670](https://github.com/rust-lang/cargo/issues/7670)
  * Comment: <https://github.com/rust-lang/cargo/issues/7670#issuecomment-841722488>

To work around this problem, our specifiers must exactly match the specifiers used by our dependencies'
dependency declarations. (That is, the `rev` / `tag` / `branch` values (or lack of them) must match.)

Currently, at least these transitively-used dependencies must be specified exactly:

```toml
once_cell = { git = "https://github.com/mesalock-linux/once_cell-sgx" }
serde = { git = "https://github.com/mesalock-linux/serde-sgx" }
serde-big-array = { git = "https://github.com/mesalock-linux/serde-big-array-sgx" }
serde_derive = { git = "https://github.com/mesalock-linux/serde-sgx" }
serde_json = { git = "https://github.com/mesalock-linux/serde-json-sgx" }
```


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


## ECALL enclave name prefixing and --use-prefix

See "[Avoiding Name Collisions]" in the Intel SGX Developer Reference.

[Avoiding Name Collisions]: https://download.01.org/intel-sgx/sgx-linux/2.13/docs/Intel_SGX_Developer_Reference_Linux_2.13_Open_Source.pdf#Avoiding%20Name%20Collisions

When linking more than one enclave library into an application,
all ECALL and OCALL function names must be unique to avoid linking collisions.
The `sgx_edger8r` tool automatically prevents OCALL name collisions by
prepending the enclave name to all bridge functions, but does not do the same
for ECALL names by default.

This means that when more than one enclave library uses a shared library with
its own ECALLs, like we do with `rtc_tenclave`, the ECALL function names of
the different instances of shared library will collide, by default.

To avoid this, we pass the `--use-prefix` option to `sgx_edger8r` to prepend
the enclave name to all untrusted proxy function names, so that the shared
library ECALLs will have a unique interface for each enclave library they're
exposed from.

This means that the shared library's trusted code and EDL will refer to a function
like `session_request`, but the untrusted code will refer to different per-enclave
instances of it, like `rtc_auth_session_request`, `rtc_data_session_request`,
and so on.

However, this means that all other references to the enclave's non-library ECALLs
will also become prefixed in the same way: the function names in the EDL will use
the unprefixed form, while the references in the untrusted code must use the
prefixed from.
