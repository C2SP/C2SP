# Community Cryptography Specification Project

## Versioning

All specifications use [Semantic Versioning](https://semver.org/). Since this is normally
intended for software, we adapt it to our specifications with the following semantics:

- 0.Y.Z indicates draft specifications.
  - Bump the version as often as you need!
  - Always bump the minor version on any material change.
- 1.Y.Z indicates "final" specifications, but these are not set in stone.
  - At this point a specification's meaning should not change.
  - Bump the patch version when making changes to the text of a specification (to improve
    it, or fix errata).
  - An extension could be defined in a separate specification, and the "main"
    specification's minor version would be incremented to include the extension.
- 2.Y.Z and above will ideally never be needed! But if we make a mistake in a finalised
  specification, this would be the pathway to recovery.
  - Otherwise these are identical to 1.Y.Z.

## Contributing

### Adding a new specification

You can either clone this repository to work locally, or you can click the "Add file"
button to write in the GitHub UI.

- Pick a meaningful, short name for the specification. This will become part of its URL
  (e.g. `https://c2sp.org/short-name`). Name your specification file `short-name.md`, and
  place it in the root of the repository.
- Write the initial specification draft! Look at existing ones for an idea of the style.
- Open a pull request!

### Updating an existing specification

You can either clone this repository and make changes locally, or you can edit a
specification directly in the GitHub UI. In either case, once you are finished, open a
pull request with your proposed updates.

## License

All specifications in this repository are licensed under CC BY 4.0
(https://creativecommons.org/licenses/by/4.0/).

All code in this repository is licensed under the BSD 1-Clause License
([LICENSE-BSD-1-CLAUSE](LICENSE-BSD-1-CLAUSE)).
