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
  forever.
* C2SP documents are developed as Markdown files on GitHub, and can include
  ancillary files such as test vectors and non-production reference
  implementations.

A [small team of stewards] maintain the overall project, enforce the [C2SP Code
of Conduct], assign [new specifications] to proposed maintainers, and may
replace lapsed maintainers, but they have no authority over individual specs.

All C2SP specifications are licensed under [CC BY
4.0](https://creativecommons.org/licenses/by/4.0/). All code and data in this
repository is licensed under the BSD 1-Clause License ([LICENSE-BSD-1-CLAUSE]).

[maintainers]: https://github.com/orgs/C2SP/teams/maintainers
[semantic versioning]: https://semver.org/
[small team of stewards]: https://github.com/orgs/C2SP/teams/stewards
[C2SP Code of Conduct]: CODE_OF_CONDUCT.md
[new specifications]: CONTRIBUTING.md#new-specifications
[LICENSE-BSD-1-CLAUSE]: LICENSE-BSD-1-CLAUSE

## Specifications

| Name | Description |  |
| --- | --- | --- |
| [`c2sp.org/age`](https://c2sp.org/age) | File encryption format | [Maintainers](https://github.com/orgs/C2SP/teams/age) |
| [`c2sp.org/age-plugin`](https://c2sp.org/age-plugin) | The age plugin stdio protocol | [Maintainers](https://github.com/orgs/C2SP/teams/age-plugin) |
| [`c2sp.org/chacha8rand`](https://c2sp.org/chacha8rand) | Fast cryptographic random number generator | [Maintainers](https://github.com/orgs/C2SP/teams/chacha8rand) |
| [`c2sp.org/https-bastion`](https://c2sp.org/https-bastion) | Bastion (reverse proxy) protocol for exposing HTTPS services | [Maintainers](https://github.com/orgs/C2SP/teams/https-bastion) |
| [`c2sp.org/jq255`](https://c2sp.org/jq255) | Prime order groups, key exchange, and signatures | [Maintainers](https://github.com/orgs/C2SP/teams/jq255) |
| [`c2sp.org/signed-note`](https://c2sp.org/signed-note) | Cleartext signed messages | [Maintainers](https://github.com/orgs/C2SP/teams/signed-note) |
| [`c2sp.org/static-ct-api`](https://c2sp.org/static-ct-api) | Static asset-based Certificate Transparency logs | [Maintainers](https://github.com/orgs/C2SP/teams/static-ct-api) |
| [`c2sp.org/tlog-checkpoint`](https://c2sp.org/tlog-checkpoint) | Interoperable transparency log signed tree heads | [Maintainers](https://github.com/orgs/C2SP/teams/tlog-checkpoint) |
| [`c2sp.org/tlog-cosignature`](https://c2sp.org/tlog-cosignature) | Witness cosignatures for transparency log checkpoints | [Maintainers](https://github.com/orgs/C2SP/teams/tlog-cosignature) |
| [`c2sp.org/tlog-tiles`](https://c2sp.org/tlog-tiles) | Static asset-based transparency log | [Maintainers](https://github.com/orgs/C2SP/teams/tlog-tiles) |
| [`c2sp.org/tlog-witness`](https://c2sp.org/tlog-witness) | HTTP protocol to obtain transparency log witness cosignatures | [Maintainers](https://github.com/orgs/C2SP/teams/tlog-witness) |
| [`c2sp.org/vrf-r255`](https://c2sp.org/vrf-r255) | Simplified ristretto255-based ECVRF ciphersuite | [Maintainers](https://github.com/orgs/C2SP/teams/vrf-r255) |
| [`c2sp.org/XAES-256-GCM`](https://c2sp.org/XAES-256-GCM) | Extended-nonce AEAD from NIST-approved components | [Maintainers](https://github.com/orgs/C2SP/teams/XAES-256-GCM) |

## Associated projects

The C2SP organization hosts three other testing-focused projects:

* [**Wycheproof**](https://github.com/C2SP/wycheproof), a large library of tests
  for cryptographic libraries against known attacks.

* [**CCTV**](https://github.com/C2SP/CCTV), the Community Cryptography Test
  Vectors, a repository of reusable test vectors.

* [**x509-limbo**](https://github.com/C2SP/x509-limbo), a suite of tests for
  X.509 certificate path validation.