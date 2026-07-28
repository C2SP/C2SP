<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="/.logo/logo-light.svg">
    <source media="(prefers-color-scheme: light)" srcset="/.logo/logo.svg">
    <img alt="The Community Cryptography Specification Project" src="/.logo/logo.svg" width="256">
  </picture>
</p>

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
supported. The former is equivalent to `@latest` and redirects to the latest
tagged version. To link to the main branch, use `@main`. GitHub URLs should not
be considered stable.

All C2SP specifications are licensed under [CC BY
4.0](https://creativecommons.org/licenses/by/4.0/). All code and data in this
repository is licensed under the BSD 1-Clause License ([LICENSE-BSD-1-CLAUSE]).

[maintainers]: https://github.com/C2SP/C2SP/blob/main/.github/MAINTAINERS.md
[semantic versioning]: https://semver.org/
[small team of stewards]: https://github.com/C2SP/C2SP/blob/main/.github/MAINTAINERS.md#stewards
[C2SP Code of Conduct]: https://c2sp.org/-/coc
[new specifications]: https://c2sp.org/-/manual#new-specifications
[LICENSE-BSD-1-CLAUSE]: https://github.com/C2SP/C2SP/blob/main/.github/LICENSE-BSD-1-CLAUSE

## Associated projects

The C2SP organization hosts three other testing-focused projects:

* [**Wycheproof**](https://github.com/C2SP/wycheproof), a large library of tests
  for cryptographic libraries against known attacks.

* [**CCTV**](https://github.com/C2SP/CCTV), the Community Cryptography Test
  Vectors, a repository of reusable test vectors.

* [**x509-limbo**](https://github.com/C2SP/x509-limbo), a suite of tests for
  X.509 certificate path validation.
