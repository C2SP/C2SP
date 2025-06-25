# Transparency Log Mirrors

This document describes how to mirror a transparency log, and how to obtain
signatures asserting that a mirror has done so.

[cosigner]: https://c2sp.org/tlog-cosignature
[cosignature]: https://c2sp.org/tlog-cosignature
[checkpoint]: https://c2sp.org/tlog-checkpoint
[tiled transparency log]: https://c2sp.org/tlog-tiles
[witness]: https://c2sp.org/tlog-witness
[percent-encoded]: https://www.rfc-editor.org/rfc/rfc3986.html#section-2.1
[subtree]: https://www.ietf.org/archive/id/draft-davidben-tls-merkle-tree-certs-05.html#name-subtrees
[subtree consistency proof]: https://www.ietf.org/archive/id/draft-davidben-tls-merkle-tree-certs-05.html#name-subtree-consistency-proofs

## Conventions used in this document

The base64 encoding used throughout is the standard Base 64 encoding specified
in [RFC 4648][], Section 4.

`U+` followed by four hexadecimal characters denotes a Unicode codepoint, to be
encoded in UTF-8. `0x` followed by two hexadecimal characters denotes a byte
value in the 0-255 range.

`[start, end)`, where `start <= end`, denotes the half-open interval containing
integers `x` such that `start <= x < end`.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][] [RFC 2119][] [RFC
8174][] when, and only when, they appear in all capitals, as shown here.

[RFC 4648]: https://www.rfc-editor.org/rfc/rfc4648.html
[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html
[RFC 6962]: https://www.rfc-editor.org/rfc/rfc6962.html

## Introduction

A mirror is a [cosigner][] that stores a copy of a log and, when signing a
[checkpoint][], provides the additional guarantee that the mirror has
durably logged and made accessible the contents of the checkpoint.

A mirror is defined by a name, a public key, and by two URL prefixes:
the *submission prefix* for write APIs and the *monitoring prefix* for read
APIs. A mirror MAY use the same value for both the *submission prefix* and the
*monitoring prefix*.

For each supported origin log, the mirror is configured with:

* The log's public key
* The log's URL prefix
* An optional list of monitoring prefixes for other mirrors for the log

The mirror maintains a copy of each origin log and serves it publicly via the
[tiled transparency log][] interface. It uses a URL prefix of
`<monitoring prefix>/<encoded origin>`, where `encoded origin` is the log's
origin, [percent-encoded][]. The checkpoint served from this prefix MUST include
a [cosignature][] from the mirror.

## Updating a Mirror

The mirror update process is designed to be safely interruptible, while avoding
large atomic operations. For each origin log, a mirror maintains the following:

* A copy of the log. The latest checkpoint of this log copy is known as the
  *mirror checkpoint*.

* A *pending checkpoint*, which is at or ahead of the mirror checkpoint. If
  ahead of the mirror checkpoint, the pending checkpoint describes entries that
  have yet to be incorporated into the mirror.

* A list of *pending entries* that have yet to be incorporated into the mirror
  checkpoint. The mirror's *next entry* is the log index of the first entry that
  is not in either the log or pending entry list.

The update process ensures that all current and past pending checkpoints are
consistent, and all pending entries are contained in the current pending
checkpoint. Thus mirrors MAY commit pending entries to the log, serving them as
entry bundles, as soon as they are added. That is, a mirror MAY use the same
underlying storage for entry bundles and pending entries, without distinguishing
between them. It is expected that most tiled log implementations will do this.

Mirrors update in three stages:

1. A mirror client updates the pending checkpoint with a signed checkpoint and a
   consistency proof.

2. A mirror client uploads new entries to the pending entry list, up to the
   pending checkpoint.

3. The mirror commits the pending entries to the log and updates the mirror
   checkpoint.

The next sections describe the HTTP endpoints used by mirror clients to update
the log.

### add-checkpoint

The mirror implements a [witness][]'s `add-checkpoint` endpoint to update its
pending checkpoint for a log:

    POST <submission prefix>/add-checkpoint

The request is handled identically to that of a witness, updating the pending
checkpoint (but not the mirror checkpoint), with the exception that it does not
need to generate and respond with any cosignatures. The mirror MAY handle the
request by internally updating the pending checkpoint and responding with an
empty response body. The mirror MUST retain the log's signature in the pending
checkpoint.

The mirror cosigner MUST NOT sign the checkpoint in this process. It MAY respond
with witness cosignatures if the mirror operator wishes to additionally provide
a separate witness service using its pending checkpoint. If so, this witness
service MUST be a distinct cosigner from the mirror cosigner, with a distinct
name. The mirror's signature is computed later, as described below.

### add-entries

The mirror implements an `add-entries` endpoint to upload entries for a supported
log:

    POST <submission prefix>/add-entries

#### Request Body

The request body MUST have `Content-Type` of `application/octet-stream` and
contain the following values, concatenated.

* 2 bytes, encoding a big-endian uint16: `log_origin_size`
* `log_origin_size` bytes, containing the log origin: `log_origin`
* 8 bytes, encoding a big-endian uint64: `upload_start`
* 8 bytes, encoding a big-endian uint64: `upload_end`
* 2 bytes, encoding a big-endian uint16: `ticket_size`
* `ticket_size` bytes, containing an opaque `ticket` value, described below
* A sequence of *entry packages*, described below

`upload_end` MUST be equal to the pending checkpoint's tree size, or that of a
previously valid pending checkpoint. `ticket` is an opaque value from the
mirror, or the empty string, to help the mirror recover past pending
checkpoints.

`upload_start` MUST be less or equal to `upload_end`. It MUST also be less or
equal to the mirror's next entry for the origin.

The request body uploads the log entries whose indices are in
`[upload_start, upload_end)`. Entries are grouped into bounded-size entry
packages. Each package has a [subtree consistency proof][] that allows the
mirror to verify and commit the entries in the package without buffering the
entire request body.

Each entry package is determined by a half-open interval `[start, end)` of log
indices. The request MUST contain entry packages whose intervals' disjoint
union, in order, is the interval `[upload_start, upload_end)`. The overall
interval MUST be divided into packages at multiples of 256, to align with the corresponding entry bundles.

More precisely, if `upload_start` is equal to `upload_end`, there are no
packages. Otherwise, let `rounded_start` be `upload_start` rounded down to a
multiple of 256, and let `rounded_end` be `upload_end` rounded up to a
multiple of 256. The request MUST contain
`num_packages = (rounded_end - rounded_start) / 256` packages. Entry
package `i`, for `0 <= i < num_packages`, MUST be computed from the interval
`[start, end)` where:

    start = max(upload_start, rounded_start + i * 256)
    end = min(upload_end, rounded_start + (i + 1) * 256)

The package MUST contain the following values, concatenated.

* The log entries in `[start, end)`, each with a big-endian uint16 length prefix
* 1 byte, encoding an 8-bit unsigned integer, `num_hashes`, which MUST be at
  most 63
* `num_hashes` [subtree consistency proof][] hash values

The subtree consistency proof is computed from the [subtree][] defined by
`[rounded_start + i * 256, end)`, and the log checkpoint with tree size
`upload_end`.

TODO: This is currently citing an individual IETF draft for subtrees, though it
is versioned and immutable. Should we, for now, copy and paste that text
somewhere here? (Subtrees are also slightly more general than needed here. Every
subtree we consider is directly contained in the target tree size.)

#### Processing

The request body has unbounded size, so the client and mirror SHOULD stream it.

The mirror processes the request as follows:

First, the mirror reads `log_origin`, `upload_start`, `upload_end`, and
`ticket`. If `log_origin` is not a known log, the mirror MUST respond with a
"404 Not Found" HTTP status code. If `upload_end` is not the tree size of a
known pending checkpoint value, the mirror MUST respond with a "409 Conflict"
HTTP status code. If `upload_start` is greater than the mirror's next entry, or
too far below the mirror's next entry, the mirror MUST also respond with a
"409 Conflict" HTTP status code.

The mirror SHOULD send these error responses without waiting for the entire
request body to be available. Conversely, the client SHOULD be prepared to
receive an error response before the request body is fully sent.

When sending a 409 response, the response body MUST have a `Content-Type` of
`text/x.tlog.mirror-info` and consist of three lines, each followed by a
newline (U+000A):

* The tree size of a valid pending checkpoint, in decimal
* The next entry, in decimal
* An opaque, possibly zero length, ticket value, encoded in base64

If the client's `upload_end` value was valid, the first line SHOULD contain
`upload_end`. This allows the client to resume an interrupted upload without
recomputing subtree consistency proofs. Otherwise, the first line SHOULD be the
tree size of the current pending checkpoint.

After receiving a 409 Conflict, the client SHOULD retry setting `upload_end` to
the tree size, `upload_start` to the advertised next entry value, and the
`ticket` to the received ticket. If a client doesn't have information on the
mirror, it MAY initially make a request with `upload_start` and `upload_end` set
to zero to obtain it.

To reduce the chance of retry failures as the mirror state changes, mirrors
SHOULD accept any of the last several pending checkpoint values as `upload_end`.
This MAY be implemented with extra state, or by storing the signed checkpoint in
the ticket. The mirror MUST authenticate any information it derives from a
ticket. For example, the ticket MAY be encrypted with a symmetric secret known
only to the mirror.

If `upload_end` and `upload_start` are valid, the mirror proceeds to read and
process each entry package. For each entry package, it MUST authenticate the
entries by verifying the subtree consistency proof: First, it reconstructs the
subtree hash based on the received entries and entries already in the log. It
then verifies the subtree consistency proof using this hash and the checkpoint
at `upload_end`.

If this verification process fails, it MUST respond with a
"422 Unprocessable Entity" HTTP status code and end processing. Otherwise, it
saves the entries as pending entries. If some entry has already been written to
the log or the pending entry list, the mirror MUST skip saving that entry.

Once all expected entry packages are successfully validated and committed, the
next entry will be greater or equal to `upload_end`. The mirror then finishes
committing entries up to `upload_end` to the log. For example, a mirror that
stores individual tiles might compute new tiles and start serving them.

Finally, the mirror performs the following steps atomically:
* Check if the mirror checkpoint's tree size is less than `upload_end`
* If so, sign the pending checkpoint of size `upload_end` and update the mirror
  checkpoint to the newly-signed checkpoint.

#### Implementation Considerations

Unlike the `add-checkpoint` endpoint, the `add-entries` endpoint is not
processed as a single atomic transaction. A mirror SHOULD permit multiple
clients to concurrently send requests to the endpoint. This avoids a
denial-of-service attack if one client begins an `add-entries` stream but pauses
it partway through. Additionally, clients and mirrors MUST continue operating
correctly if an `add-entries` stream is interrupted. The API is designed to
support this with minimal synchronization.

When checking the `upload_start` and `upload_end` values, the mirror MUST act on
*some* valid copy of its pending checkpoint and next index state. However, it
MAY act on stale data without impacting correctness of the protocol. That is, it
is not necessary to globally synchronize this check with `add-checkpoint`
handling, or other instances of `add-entries`.

When committing authenticated entries to the pending entries list, it is
possible that, due to a concurrent instance of `add-entries`, some entries have
already been added to the pending entries list or the mirror. Mirrors MUST
correctly handle this case and continue operating correctly. This may require
synchronization of individual log resources. In doing so, the mirror MAY assume
that the two copies of the entries are identical. They will both be proven
consistent with the pending checkpoints.

When updating the mirror checkpoint to `upload_end`, it is possible that some
concurrent instance of `add-entries` has already updated the mirror checkpoint to `upload_end`
or past it. In this case, the mirror MUST NOT rewind the checkpoint and MUST
instead skip the update.

Entry packages are divided at multiples of 256 to align with the entry bundle
representation in the tiled log interface. It is expected that most
implementations will compute exactly one entry bundle from each entry package
and commit it directly to log storage when the package is authenticated.

A mirror that uses a different representation MAY buffer entry packages and defer
committing them. For example, if the mirror internally stores entry bundles of
size 512, it might commit entry packages two at a time.

A mirror MAY process an entry package without waiting for the previous entry
package to be durably committed to storage. However, the mirror MUST NOT sign
or update its mirror checkpoint until all entries are durably committed. If the
mirror commits entries out of order, it MUST correctly compute the next entry to
be the *first* missing entry, even if some subsequent entries have been
committed. Mirror clients will then reupload the subsequent entries.

A mirror MAY additionally implement other update processes, provided it continues
to correctly operate `add-entries` and never violates its cosigner requirements
on mirror checkpoints.
