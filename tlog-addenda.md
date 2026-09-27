---
description: Detachable (and optionally redactable) data committed by a transparency log
---

> [!WARNING]
> This is the editor's copy of this specification.
> For a stable rendered reference, use [c2sp.org/tlog-addenda](https://c2sp.org/tlog-addenda).

# Transparency Log Addenda

This document describes mechanisms for attaching data to a transparency log,
such that the data becomes discoverable and manageable by common tooling,
but without directly introducing the data to the log's entries.

We call such attached data an *addendum*.

The mechanism described by this document is, as a whole, optional.
Transparency log instances do not need to choose to align their content with this spec.
For those that do, there are three main pieces of value:

1. It is possible to store arbitrarily sized content as an addendum.
2. This spec establishes conventions that shared tooling --
   for example, log explorers and mirroring tools --
   can use to operate over the addenda of any conforming log without needing instance-specific knowledge.
3. This spec addresses recurring practical design subjects such as redaction in a concrete way.


## Conventions used in this document

The hex encoding of a byte string is its fixed-length lowercase Base 16 encoding,
as specified in [RFC 4648][], Section 8, without padding.
`0x` followed by two hexadecimal characters denotes a byte value in the 0-255 range.
`||` denotes concatenation.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][] [RFC 2119][] [RFC
8174][] when, and only when, they appear in all capitals, as shown here.

[RFC 4648]: https://www.rfc-editor.org/rfc/rfc4648.html
[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html


## Motivation

Transparency logs publish ordered, witnessed commitments while leaving applications free to define their entries.
It's unstated, but implicit, that excessively large entries are to be avoided.
There are two major reasons for this: one, large entries may be burdensome to transfer during monitoring;
and two, that because entries are part of the log's core structure, they become impossible to redact without retiring the log.
When rolling out transparency logs in new domains, this forces decisions about log entry structure.

In practice, the solution to this, informally, is "store a hash instead of the full content".
Monitors can then verify the log without transferring the content,
and consumers fetch it only when needed.
Content referenced by many entries is stored, and fetched, only once.
The content can later be removed without changing the tree or any proof,
which also enables redaction where needed.

In this document, we standardize that concept:
we define a minimal necessary amount of structure
to make that pattern standardized and legible
such that the ecosystem can develop general tools (such as log viewers and mirroring tools)
that do not need to rely on instance-specific knowledge.

We also discuss the common subjects of log entry design:
what may be reasonably externalized,
and what must stay in the log directly for monitoring to be effective.


## Overview

An *addendum* is an opaque byte string.
Its *digest* is the SHA-256 hash of those bytes.

- A submitter stores the addendum in the *addenda store*, keyed by its digest.
- The submitter commits the digest as part of a transparency log entry.
- Proving the log's consistency, or an entry's inclusion, never requires fetching an addendum.
- Anyone inspecting content may fetch an addendum by its digest and check it by re-hashing.
- To redact, the operator stops serving the addendum; the log is untouched.

The log stays the source of truth for what was committed, and in what order.
The addenda store holds the bytes behind each commitment.

In order to make the addendum digests mechanically legible,
and do so with a minimum of overhead and a minimum of stricture on the entry format,
we define:

- a *digest indication format* which can be suffixed to any other log entry content
  to identify the position of addenda-referencing digests in that content.
- a marker that can be advertised at the scale of the log itself
  so that tools inspecting a log can know whether they should look for
  the addenda digests.


## Parameters

Addenda are served under the same URL prefix as the transparency log they accompany,
as siblings to e.g. the log's checkpoint and other static assets.

This version of the addenda spec contains no other parameters.


## The addenda store

An addendum is served at

	<prefix>/addenda/<s0>/<s1>/<digest>

with `Content-Type: application/octet-stream` if served over an HTTP transport,
or can be served directly from a filesystem.

`<digest>` is the addendum's SHA-256 digest, in lowercase hexadecimal encoding.

`<s0>` and `<s1>` are the first and second bytes of the digest,
each as two lowercase hex characters --
that is, `<s0>` is `<digest>[0:2]` and `<s1>` is `<digest>[2:4]`.

For example, a store with *prefix* `https://log.example.org/data`
serves the addendum whose SHA-256 digest is
`9f86d08a0c3bf4fd15d6c15b0f188455a1b2b0b822cd015ac7d659a2fea00a08` at

	https://log.example.org/data/addenda/9f/86/9f86d08a0c3bf4fd15d6c15b0f188455a1b2b0b822cd015ac7d659a2fea00a08

The bytes of an addenda entry are immutable.
Redaction, defined below, removes the resource; it does not change it.

### Verification

A consumer that fetches an addendum MUST verify it
by computing the SHA-256 hash of the content and checking that its hex encoding equals `<digest>`.
Content that does not hash to the requested digest MUST be rejected.

A consumer MUST NOT treat a fetched addendum as trustworthy
until it has both verified the hash
and verified that `<digest>` is committed by a log entry whose inclusion has been proven.
The store itself is untrusted:
all authority is transitive from a log checkpoint,
down through the log entry containing the addendum digest,
and then to the addenda body from the digest.


## Log entries

An addendum is bound to a log by the inclusion of its digest in a log entry.

The addenda specification intentionally does not fully dictate the structure of a log entry.
Instead, we define a format that can be appended to the end of any entry,
and indicates where in the entry that digests for addenda data are found.

In this way, the bulk of a log entry's data is still composed of whatever data that application desires,
and in whatever encoding that application already uses.

### The digest indication format

A simple format suffixed to the end of log entry content indicates where digests can be found within that content.
It is parsed from the end of the document, backwards
(and thus imposes no stricture on any of the content that comes before it):

- The final byte is a count `N`, from 0 to 255, of digests to be found in the content.
- The `N * 4` bytes before it are `N` offsets.
  Each is a 4-byte big-endian unsigned integer.
- Each offset is a position, in bytes from the start of the entry, where a 32-byte SHA-256 digest appears.

So an entry has the shape:

	<application content, including the digests> || <offset 0> || ... || <offset N-1> || <N>

An entry with no addenda is just its application content followed by a single `0x00` byte.

A reader takes the final byte as `N`, reads the `N` preceding offsets,
and reads a 32-byte digest at each.
The index points *into* the entry rather than restating the digests,
so a digest the application already holds is never written twice.

Writers SHOULD list offsets in ascending order.
Readers MUST accept offsets in any order.


## Signalling use of Addenda

Because the digest indication format in the entries is compact,
it's also effectively indistinguishable from arbitrary trailing bytes.
Tools cannot reasonably infer its use from log entries themselves.

A log whose entries use the digest indication format signals this by serving a marker resource at

	<prefix>/addenda.v1

The body of the marker MUST be empty.

The presence of the marker asserts that *every* entry in the log ends with a digest indication index --
including entries with no addenda, which end in a single `0x00` byte.


## Relationship to Monitoring

Because the addenda spec is about indirecting data outside of the log itself,
it's also a natural place to discuss redaction.

### Redaction

Redaction refers to refusing to serve a piece of addenda data.
Reasons this may be desirable are out of scope of this document,
but examples may include detection of private information, unlawful content,
or material subject to a valid erasure demand.

Redaction of addenda data is possible because it only involves data outside the transparency log:
the log itself is unaffected; further appends and witnessing proceed as usual; etc.

#### Consideration: Blinding

If there is a need to prevent recovery by guess-and-check after redaction of a low-entropy or otherwise guessable addendum,
its content SHOULD include at least 16 bytes of nonce material from a cryptographically secure random source,
which the consuming application handles according to its own format.
The exact composition is not in the scope of this document.

### Partitions

It is common for a log and monitors of it to want to verify that application-specific properties hold
across a series of related log entries.

For this to remain possible in a system which also permits redactions,
it is necessary to design the log entry format so that any information that defines "related"
remains *in the entry itself* and is not found only in the addendum.

We refer to such information as "partition keys".

This specification does not mandate any structure for partition keys.
Such data is application specific; an application may have one or many partition keys;
and they could be arbitrarily structured.
For the purpose of this spec, we only identify the subject in order to make it clear:
partition key data belongs in the log entry, not in an addenda.
If a redaction of an addenda would make it unclear which partitions a log entry is related to,
then it would effectively destroy the ability to verify any properties over that partition,
because there would be no way to know if any redacted addenda applies to that partition or not.
When designing the format of log entries, this must be considered if the log will support redaction.

#### Consideration: Verifiable maps

A verifiable map, such as a Merkle Patricia Trie whose root is committed in the log,
is a useful companion to the partition value concept.
The exact composition is not in the scope of this document.


## Notably unspecified

- This specification has standardized on SHA-256.  Use of other hashes is unspecified.
- This specification only describes binary encodings of digests.  Use of other encodings is unspecified.


## Acknowledgements

This design follows the static-asset layout conventions of [tiled transparency logs][],
and draws on the "log a hash, store the content elsewhere" practice
long used across the transparency-log community.

[tiled transparency logs]: https://c2sp.org/tlog-tiles
