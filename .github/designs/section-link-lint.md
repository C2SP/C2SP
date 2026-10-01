# Design: section-link linting

Proposal only; no implementation or PR yet.

## Goal

Reject newly broken C2SP section links, including links broken indirectly by
changes to their destination. Protect floating references in published versions,
not just references in the current source tree. Offer an actionable compatibility
anchor suggestion when a previously valid destination disappears.

Do not require every historical heading to survive forever: the compatibility
requirement applies to anchors referenced by the checked corpus. References from
outside that corpus cannot be discovered by this linter.

## Link resolution

Use the website's actual routing and the manual's version-selection rules.
In particular, an unversioned URL is not always an implicit `@main`: it selects
the highest non-prerelease tag, otherwise the highest prerelease tag, otherwise
main. The website also falls back to main for explicit `@latest` without tags.

For each C2SP section link, perform these checks:

| Destination | Current-resolution check | Future-release check |
| --- | --- | --- |
| `foo@v1.0.0#bar` | `foo.md` at `foo/v1.0.0` | None |
| `foo@main#bar` | Candidate main's `foo.md` | Same check |
| `foo@latest#bar` | Currently selected release, or candidate main if untagged | Candidate main's `foo.md` |
| `foo#bar` | Same selection as `@latest` | Candidate main's `foo.md` |
| `#bar` | Containing document at its own revision | None |

Candidate main means the checked-out working tree locally and the proposed merge
tree in PR CI, not a network fetch of the deployed main branch.

The future check assumes each destination's main can eventually become latest;
it does not assume that all specs will be released simultaneously. Thus a new
floating reference to an unreleased heading fails the current-resolution check,
even if it passes the future check. Use `@main` until the destination is released.
A compatibility anchor added on main likewise does not repair a currently
broken released destination until it is released.

Missing specs and versions are errors, not empty anchor sets. Reject malformed
C2SP spec destinations rather than silently skipping them. Handle fragments with
URL parsing and percent-decoding, without lowercasing the fragment or treating
`+` as a space. An empty fragment means the document itself.

Share route classification with the website: project document routes and the
`sunlight` redirect must not be mistaken for missing specs. Index served project
documents too. Explicit commit URLs can be checked on demand using the website's
reachability rule; do not crawl all historical commits. CCTV redirects, static
assets, and external hosts are outside this section check.

## Corpus and graph

Build document records containing anchors, outgoing links, and source locations:

* Candidate main: all root specification Markdown and served project documents.
* Every recognized spec tag: only that tag's corresponding `<spec>.md`, not every
  spec file present in that historical repository tree.
* Explicitly referenced commit snapshots, loaded on demand.

Check links from all published spec tags, including old releases and prereleases.
A link from `consumer@v1.0.0` to `producer@main#old-name` still imposes a
compatibility requirement even after consumer's main stops referencing it.
Conversely, a pinned link to `producer@v1.0.0#old-name` imposes no requirement on
producer's main.

Build a reverse index from destination/fragment to referring documents. Report
one removed-anchor failure with its referrers rather than a separate noisy error
for every occurrence. Cache parsed documents by blob identity and rendering
context; the current corpus is small enough to check in full.

Relative fragment links stay bound to their containing revision. Root-relative
C2SP routes resolve as they do on the website. Parse real Markdown inline links,
reference links, autolinks, and raw HTML links; code samples, comments, and unused
reference definitions do not create graph edges. Existing formatting rules remain
separate from link checks and are not retroactively imposed on old tags.

## Compatibility anchors

Bless this syntax in the manual:

```markdown
<a id="old-section-name"></a>
<a id="even-older-section-name"></a>

## New section name
```

The section retains its normal generated heading ID and permalink. The empty
anchors supply additional destinations immediately before the heading. No custom
Markdown extension, redirect registry, or automatic heading-ID replacement.
The blank line before the heading is required by the documented convention.

Preserve the exact old ID, including any duplicate-heading suffix. Multiple
aliases are allowed. Reject empty aliases and collisions with any other rendered
ID or legacy named anchor in the same document; do not silently renumber
automatic heading IDs to accommodate aliases. Repeated generated IDs are also
errors. Recognize historical `<a name="...">` anchors, while documenting `id`
as the preferred syntax.

Parse HTML nodes, not regular expressions over Markdown source, so an example
anchor inside a code fence does not become a valid destination.

## Shared implementation

Extend the existing `.github/lint` command rather than adding a crawler.

Factor reusable document preparation and analysis into the website module,
building on `.website/spec`. Both website rendering and linting must use the same
Markdown extensions, front-matter removal, content transformations, heading
text extraction, and slug allocation. Return source positions alongside links
and anchors. Share pure route/version selection helpers too; keep repository
loading and CLI reporting separate from parsing.

Rendered HTML is the ground truth. Tests must compare the analyzer's destinations
with actual rendered destinations, including HTML IDs, legacy named anchors,
footnotes, duplicate headings, entities, Unicode, math, and aliases. The existing
title handling needs attention: the renderer removes the source H1 and the
template currently emits an H1 without its ID, whereas the linter counts its
slug. Carry that ID into the displayed title rather than continuing to accept
nonexistent title anchors. Include template IDs in collision checks.

Use local Git objects for tagged documents. No HTTP requests or credentials are
needed for linting after checkout. Fetch full history and tags in CI and fail
clearly on incomplete/shallow inputs rather than silently omitting releases.

## Diagnostics and existing debt

Analyze both base and candidate snapshots with the same checker and tag inventory.
For PRs, the base is the target branch commit corresponding to the merge checkout;
for local runs, accept an explicit `--base`. With no base, perform a full audit.

Use stable failure identities (source document/revision, destination, check kind),
not line numbers. Fail on newly introduced failures; report existing debt
separately. This applies to immutable historical documents too, which cannot be
edited to repair pre-existing pinned-link mistakes. New occurrences in edited
sources must not inherit an exemption just because an identical broken URL
already appeared elsewhere; compare link occurrences using the source diff.
Do not use broad per-spec suppressions.

Compare base and candidate anchor inventories to distinguish removal from a
destination that never existed. If a floating link resolved before but its
anchor disappeared, annotate the destination's changed heading/file and list
referring source locations and revisions:

```text
producer.md:84: removed anchor #old-name is still referenced
  consumer.md:42: https://c2sp.org/producer@main#old-name
  consumer@v1.0.0:37: https://c2sp.org/producer#old-name
  The latter will break when producer's main becomes latest.

  If this section was renamed, preserve the old destination by adding:
    <a id="old-name"></a>

  immediately before the replacement heading.
```

Do not claim to know the replacement heading unless the diff makes it clear.
Suggestions are not automatic fixes: removal can represent a split, merge, or
semantic change. For a typo or nonexistent version, point at the referring link
instead of suggesting a compatibility anchor.

## CI and release integration

Run on every PR, including spec-only edits, and on main/tag updates. Run both
the linter tests and website tests when their shared implementation changes.
Emit concise text locally and GitHub file/line annotations in CI.

Check `.new-tag` proposals against a virtual post-tag inventory as well as the
current one. Load the proposed spec from the recorded commit, which need not be
the tip of main. Validate its outgoing links and re-evaluate latest resolution.
Run the same check before the tag-creation action pushes any tags, so tagging an
older commit cannot bypass the check. Proposed tags must not make a currently
nonexistent pinned link pass the current-resolution check.

## Acceptance tests

Use temporary Git repositories with real tags and a base/candidate pair:

* Correct and broken pinned links, with different headings in tagged/main copies.
* Explicit main, latest, and bare URLs; no tags, prerelease-only tags, and a
  stable release alongside a numerically newer prerelease.
* Rename referenced only by an old tagged source; compatibility alias repairs it.
* Pinned inbound references do not unnecessarily freeze main's headings.
* Future-only breakage and links valid only after an unreleased change.
* Multiple aliases, alias removal, collisions, generated suffixes, and code
  samples that contain fake anchors or fake links.
* Percent-encoded Unicode fragments, reference links, HTML links, title anchors,
  footnotes, project routes, and redirects.
* Existing historical failures remain visible without blocking unrelated work;
  new broken occurrences and newly broken historical edges fail.
* Deleted destination files, missing tags, incomplete checkout, and proposed
  tags targeting older commits.

## Suggested implementation sequence

1. Shared document analysis, renderer parity tests, and documented alias syntax.
2. Git inventory and current/future graph checks, with regression diagnostics.
3. CI and proposed-tag checks; audit existing failures and fix mutable sources.

No PR is opened until the design is agreed.
