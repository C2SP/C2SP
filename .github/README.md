# The Community Cryptography Specification Project

The Community Cryptography Specification Project (C2SP) is a project that
facilitates the maintenance of cryptography specifications using software
development methodologies. In other words, C2SP applies the successful processes
of open source software development and maintenance to specification documents.

* C2SP decisions are **not based on consensus**. Instead, each spec is developed
  by its [maintainers], who are responsible for reviewing and accepting changes,
  just like open source projects. This enables rapid, focused, and opinionated
  development. Since C2SP produces **specifications, not standards**, technical
  disagreements can be ultimately be resolved by forking.
* C2SP specs are **updateable**, and follow [semantic versioning]. Most
  specifications are expected to start at v0.x.x while in “draft” stage, then
  stay at v1.x.x for as long as they maintain backwards compatibility, ideally
  forever. Drafts are expected to bump the minor version on breaking changes.
* C2SP documents are developed as Markdown files on GitHub, and can include
  ancillary files such as test vectors and non-production reference
  implementations.

A [small team of stewards] maintains the overall project, enforces the [C2SP
Code of Conduct], assigns [new specifications] to proposed maintainers, and may
intervene in case of maintainer conflict or to replace lapsed maintainers, but
they are otherwise not involved in the development of individual specs (in their
steward capacity).

Versions are tracked as git tags of the form `<spec-name>/vX.Y.Z` like
`age/v1.2.3`.

Specifications should be linked using their c2sp.org short-links.
`https://c2sp.org/<spec-name>` and `https://c2sp.org/<spec-name>@<version>` are
supported. (The former currently redirects to the specification in the main
branch, this may change in the future to the latest tagged version of the spec.)
GitHub URLs should not be considered stable.

All C2SP specifications are licensed under [CC BY
4.0](https://creativecommons.org/licenses/by/4.0/). All code and data in this
repository is licensed under the BSD 1-Clause License ([LICENSE-BSD-1-CLAUSE]).

[maintainers]: MAINTAINERS.md
[semantic versioning]: https://semver.org/
[small team of stewards]: MAINTAINERS.md#stewards
[C2SP Code of Conduct]: CODE_OF_CONDUCT.md
[new specifications]: CONTRIBUTING.md#new-specifications
[LICENSE-BSD-1-CLAUSE]: LICENSE-BSD-1-CLAUSE

## Specifications

| Name | Description |  |
| --- | --- | --- |
| [`c2sp.org/age`](https://c2sp.org/age) | File encryption format | [Maintainers](MAINTAINERS.md#age) |
| [`c2sp.org/age-plugin`](https://c2sp.org/age-plugin) | The age plugin stdio protocol | [Maintainers](MAINTAINERS.md#age-plugin) |
| [`c2sp.org/BLAKE3`](https://c2sp.org/BLAKE3) | A fast cryptographic hash function (and PRF, MAC, KDF, and XOF) | [Maintainers](MAINTAINERS.md#BLAKE3) |
| [`c2sp.org/chacha8rand`](https://c2sp.org/chacha8rand) | Fast cryptographic random number generator | [Maintainers](MAINTAINERS.md#chacha8rand) |
| [`c2sp.org/det-keygen`](https://c2sp.org/det-keygen) | Deterministic key pair generation from seed | [Maintainers](MAINTAINERS.md#det-keygen) |
| [`c2sp.org/https-bastion`](https://c2sp.org/https-bastion) | Bastion (reverse proxy) protocol for exposing HTTPS services | [Maintainers](MAINTAINERS.md#https-bastion) |
| [`c2sp.org/jq255`](https://c2sp.org/jq255) | Prime order groups, key exchange, and signatures | [Maintainers](MAINTAINERS.md#jq255) |
| [`c2sp.org/signed-note`](https://c2sp.org/signed-note) | Cleartext signed messages | [Maintainers](MAINTAINERS.md#signed-note) |
| [`c2sp.org/static-ct-api`](https://c2sp.org/static-ct-api) | Static asset-based Certificate Transparency logs | [Maintainers](MAINTAINERS.md#static-ct-api) |
| [`c2sp.org/tlog-checkpoint`](https://c2sp.org/tlog-checkpoint) | Interoperable transparency log signed tree heads | [Maintainers](MAINTAINERS.md#tlog-checkpoint) |
| [`c2sp.org/tlog-cosignature`](https://c2sp.org/tlog-cosignature) | Witness cosignatures for transparency log checkpoints | [Maintainers](MAINTAINERS.md#tlog-cosignature) |
| [`c2sp.org/tlog-mirror`](https://c2sp.org/tlog-mirror) | HTTP protocol to mirror transparency logs | [Maintainers](MAINTAINERS.md#tlog-mirror) |
| [`c2sp.org/tlog-tiles`](https://c2sp.org/tlog-tiles) | Static asset-based transparency log | [Maintainers](MAINTAINERS.md#tlog-tiles) |
| [`c2sp.org/tlog-witness`](https://c2sp.org/tlog-witness) | HTTP protocol to obtain transparency log witness cosignatures | [Maintainers](MAINTAINERS.md#tlog-witness) |
| [`c2sp.org/vrf-r255`](https://c2sp.org/vrf-r255) | Simplified ristretto255-based ECVRF ciphersuite | [Maintainers](MAINTAINERS.md#vrf-r255) |
| [`c2sp.org/XAES-256-GCM`](https://c2sp.org/XAES-256-GCM) | Extended-nonce AEAD from NIST-approved components | [Maintainers](MAINTAINERS.md#XAES-256-GCM) |

## Associated projects

The C2SP organization hosts three other testing-focused projects:

* [**Wycheproof**](https://github.com/C2SP/wycheproof), a large library of tests
  for cryptographic libraries against known attacks.

* [**CCTV**](https://github.com/C2SP/CCTV), the Community Cryptography Test
  Vectors, a repository of reusable test vectors.

* [**x509-limbo**](https://github.com/C2SP/x509-limbo), a suite of tests for
  X.509 certificate path validation.
