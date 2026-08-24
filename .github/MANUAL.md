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

[maintainers]: https://c2sp.org/-/maintainers
[semantic versioning]: https://semver.org/
[small team of stewards]: https://c2sp.org/-/maintainers#stewards
[C2SP Code of Conduct]: https://c2sp.org/-/coc
[new specifications]: #new-specifications

## Consuming specifications

### Versioning

v0.x.y versions should be considered draft specifications, and may be updated
with breaking changes. v1.x.y versions can be considered stable specifications
and suitable interoperation targets.

All tagged versions (both v0.x.y and v1.x.y) are immutable.

### Permanent links

Specifications should be linked using their c2sp.org short-links, like
`https://c2sp.org/<spec-name>` and `https://c2sp.org/<spec-name>@<version>`.

`https://c2sp.org/<spec-name>` redirects to the latest non-prerelease tagged
version of the specification, if any. Otherwise, it redirects to the latest
prerelease version, if any. Otherwise, it renders the main branch of the
specification.

`@latest` always renders the latest tagged version of the specification, with
the same logic as above (non-prerelease preferred over prerelease).

`@main` always renders the main branch of the specification.

`@<version>` contents are immutable.

GitHub URLs should not be considered stable.

### License

All C2SP specifications are licensed under [CC BY 4.0].

All code and data in the C2SP repository is licensed under the BSD 1-Clause
License ([LICENSE-BSD-1-CLAUSE]).

[LICENSE-BSD-1-CLAUSE]: https://github.com/C2SP/C2SP/blob/main/.github/LICENSE-BSD-1-CLAUSE
[CC BY 4.0]: https://creativecommons.org/licenses/by/4.0/

## Maintaining specifications

Anyone is welcome to contribute new specifications or collaborate on existing
documents, in accordance with the [C2SP Code of Conduct] and the relevant
licenses.

Note that when contributing to a certain specification, its maintainers are
responsible for accepting or rejecting changes, and different maintainers may
have different preferences for contributions.

### New specifications

New specifications are approved by a quorum of two stewards and assigned to one
or more maintainers.

If you wish to maintain a new spec, [open a new specification request]. The
proposal must include:

* A description of the specification sufficient to assess its scope. A draft is
  useful but not required.

* The proposed short name matching the regex `[a-zA-Z0-9\-]+`. This will become
  part of its URL (e.g. `https://c2sp.org/short-name`).

* The proposed maintainers.

See [#45](https://github.com/C2SP/C2SP/issues/45) for an example.

[open a new specification request]: https://github.com/C2SP/C2SP/issues/new?template=new.md

### Formatting

Specifications are rendered from Markdown in the GitHub flavor, with footnote
support.

A YAML front-matter block is required at the top of each specification, with a
`description` field containing a short description of the specification, for the
homepage.

After the front-matter, the following warning boilerplate must be included. It
will be removed by the c2sp.org renderer.

```
> [!WARNING]
> This is the editor's copy of this specification.
> For a stable rendered reference, use [c2sp.org/<spec-name>](https://c2sp.org/<spec-name>).
```

Next, a single top-level heading must be included with the title of the specification.

### GitHub permissions

Each maintainer has access to approve and merge any PR to their specifications
(both to the `.md` file in the root of the repository and to anything under a
directory named like the spec), as well as to manage the issue tracker.

Please only take maintainer actions on issues related to your spec.

Maintainers also have write access to the [CCTV] repository, which is used to
store test vectors for specifications.

[CCTV]: https://github.com/C2SP/CCTV

### GitHub commits

Please use `<spec-name>:` prefixes in commit messages to indicate which
specification the commit is related to.

For example:

```
age: add new recipient type for hybrid tagged native age
```

### GitHub issues

Like commits, please use `<spec-name>:` prefixes in issue titles to indicate
which specification the issue is related to.

### Tagging new versions

Versions are tracked as git tags of the form `<spec-name>/vX.Y.Z` like
`age/v1.2.3`.

To tag a new version, a maintainer creates a file named `<spec-name>/.new-tag`
(e.g. `age/.new-tag`) with the following contents:

```
vX.Y.Z
<full 40-character commit hash>
```

The first line is the version (a valid semver like `v1.2.3`), and the second
line is the full commit hash to tag. The commit must be reachable from the main
branch.

Merge this file to main, and a GitHub Action will create the tag
`<spec-name>/v1.2.3` and remove the `.new-tag` file.

### Updating maintainers

The set of maintainers for a specification can unanimously request to add or
remove maintainers by [opening a maintainers change request]. The request will
be serviced by a steward, without requiring a quorum.

If unanimous agreement cannot be reached, that can be treated as either a
maintainer conflict, or a lapsed maintainer, and the stewards may intervene to
resolve the situation.

[opening a maintainers change request]: https://github.com/C2SP/C2SP/issues/new?template=maintainers.md

### OIDs

Specification maintainers may request OID assignments for their specifications
under the C2SP Private Enterprise Number (PEN) arc 1.3.6.1.4.1.64829 by [opening
an OID assignment request]. The request will be serviced by a steward, without
requiring a quorum.

Assigned OIDs are recorded in the [C2SP OID registry].

[C2SP OID registry]: https://c2sp.org/-/oids
[opening an OID assignment request]: https://github.com/C2SP/C2SP/issues/new?template=oid.md

### IANA registries

If requesting a codepoint assignment in an IANA registry, use a [permanent
link](#permanent-links) like `https://c2sp.org/<spec-name>@<version>`.

See the [AEAD Algorithms registry] for an example.

[AEAD Algorithms registry]: https://www.iana.org/assignments/aead-parameters#aead-parameters-2

## Stewarding C2SP

### New specification playbook

Stewards follow these instructions when creating a new spec, after it was
approved per the process described in the ["New specifications" section][new
specifications] above.

* Create a new [@C2SP/maintainers sub-team](https://github.com/orgs/C2SP/teams)
  and add the new maintainers.

* Create a `<spec-name>.md` file with contents:

```markdown
---
description: <!-- insert spec description here -->
---

> [!WARNING]
> This is the editor's copy of this specification.
> For a stable rendered reference, use [c2sp.org/<spec-name>](https://c2sp.org/<spec-name>).

# <!-- insert spec title here -->
```

* Run `cd .github && go generate ./...`.

* Open a PR with all the changes above, mark it "Closes #NNN" for the issue
  number requesting the new spec, and have it approved by another steward.
