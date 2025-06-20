# Tiled Transparency Logs

This document specifies an efficient HTTP API to fetch the signed checkpoint,
Merkle Tree hashes, and entries of a transparency log containing arbitrary
entries.

## Conventions used in this document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][] [RFC 2119][] [RFC
8174][] when, and only when, they appear in all capitals, as shown here.

[RFC 8446]: https://www.rfc-editor.org/rfc/rfc8446.html
[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html

## Parameters

A tiled transparency log is defined by a URL *prefix*, a [checkpoint][] origin,
and one or more [signed note][] public keys.

The origin line SHOULD be the schema-less URL prefix of the log with no trailing
slashes. For example, a log with *prefix* `https://rome.ct.example.com/tevere/`
will use `rome.ct.example.com/tevere` as the checkpoint origin line.

## APIs

The entries in the tree, as well as ancillary information such as proofs and
signed tree heads are exposed not through dynamic APIs like those defined in
[RFC 6962][], but as a finite set of static resources which can be fetched with
HTTP GET requests, and which can be efficiently cached and compressed.

Note that all Merkle tree cryptographic operations are as specified by RFC 6962,
so these APIs can be thought of as an alternative encoding format for the same
data. The hashing algorithm is defined to be SHA-256.

### Checkpoints

The Signed Tree Head MUST be served as a [checkpoint][] at

	<prefix>/checkpoint

with `Content-Type: text/plain; charset=utf-8`.

This endpoint is mutable, so its headers SHOULD prevent caching beyond a few
seconds.

If the log is public, or is interacting in any way with the public witness
network, the checkpoint MUST carry at least one Ed25519 signature by the log.
The checkpoint MAY carry additional signatures of other types, by the log or
otherwise.

### Merkle Tree

Instead of serving consistency and inclusion proofs for arbitrary entries and/or
tree sizes, logs serve the Merkle Tree as a set of “tiles”: concatenated
sequences of consecutive Merkle Tree Hashes at a certain tree height. Clients
can fetch all the tiles they need in parallel and compute any desired proof.

Tiles are served at

	<prefix>/tile/<L>/<N>[.p/<W>]

with `Content-Type: application/octet-stream`.

`<L>` is the “level” of the tile, and MUST be a decimal ASCII integer between 0
and 63, with no additional leading zeroes.

`<N>` is the index of the tile within the level. It MUST be a non-negative
integer encoded into zero-padded 3-digit path elements. All but the last path
element MUST begin with an `x`. For example, index 1234067 will be encoded as
`x001/x234/067`. (This allows storing tile resources efficiently in a filesystem
without file/directory conflicts, and serving them directly.)

The `.p/<W>` suffix is only present for partial tiles, defined below. `<W>` is
the width of the tile, a decimal ASCII integer between 1 and 255, with no
additional leading zeroes.

This endpoint is immutable, so its caching headers SHOULD be long-lived.

Full tiles MUST be exactly 256 hashes wide, or 8,192 bytes.  At “level 0” tiles
contain leaf hashes. At “level 1” and above, each hash in a tile is the Merkle
Tree Hash of a *full* tile at the level below.

More formally, in the language of RFC 6962, Section 2.1, the *n*-th tile at
level *l*, with *n* and *l* starting at 0, is the sequence of the following
Merkle Tree Hashes, with *i* from 0 to 255:

    MTH(D[(n * 256 + i) * 256**l : (n * 256 + i + 1) * 256**l])

The tile's *start index* is defined to be `n * 256**(l+1)`. Its *end index* is
defined to be `(n + 1) * 256**(l+1)`. The Merkle Tree Hashes in the tile
together span the range of entries `D[start_index : end_index]`.

Note that a tile represents the entire subtree of height 8 with its hashes as
the leaves. The Merkle Tree levels between those expressed by the tile hashes
are reconstructed by hashing the leaves.

#### Partial Tiles

Some or all of the rightmost tiles in a tree will always be _partial_. A partial
tile contains between 1 and 255 hashes, and MUST NOT be hashed into a tile at
the level above.

The partial tile at level *l* for a tree of size *s* has `floor(s / 256**l) mod
256` entries. Empty tiles MUST NOT be served.

For example, a tree of size 70,000 will be represented by 273 full level 0
tiles, one partial level 0 tile of width 112, one full level 1 tile, one partial
level 1 tile of width 17, and one partial level 2 tile of width 1. Note that a
tree of size 256 will be represented by a full level 0 tile and a partial level
1 tile of width 1.

Logs MUST serve partial tiles corresponding to tree sizes for which a checkpoint
was produced, but MAY delete any partial tile once the corresponding full tile
is either available, or has been removed by the pruning criteria below. Clients
MUST NOT fetch arbitrary partial tiles without verifying a checkpoint with a
size that requires their existence, and MAY fetch the full tile in parallel as a
fallback in case the partial tile is not available anymore.

### Log entries

The log entries are served as a “entry bundles” at

	<prefix>/tile/entries/<N>[.p/<W>]

with `Content-Type: application/octet-stream`.

`<N>` and `.p/<W>` have the same meaning as in Merkle Tree tile paths above.

Entry bundles SHOULD be compressed at the HTTP layer. Logs MAY use
`Content-Encoding: gzip` with no negotiation, or any compression algorithm
requested by the client with `Accept-Encoding`. Clients SHOULD include `gzip`
and `identity` in their `Accept-Encoding` headers.

This endpoint is immutable, so its caching headers SHOULD be long-lived.

Entry bundles are sequences of big-endian uint16 length-prefixed log entries.
Each entry in a bundle hashes to the corresponding entry in the corresponding
“level 0” Merkle Tree tile. Hashing of entries is performed according to RFC
6962, Section 2.1.  As above, a full bundle has a *start index* and *end index*,
defined the same as above for “level 0”.

TODO: check if current logs need bigger leaves.

A client, such as a Monitor, that “tails” a rapidly (> 200 entries per
checkpoint) growing log SHOULD, as an optimization, avoid fetching partial entry
bundles when possible. If applying this optimization, the client MUST fetch the
corresponding partial “level 0” tile, and use that to verify the current
checkpoint. When fetching a subsequent checkpoint, the client MUST verify its
consistency with the current checkpoint. If an entry bundle remains partial for
too long (as defined by client policy), the client MUST fetch it to prevent
delaying entries from being processed indefinitely.

Logs MAY serve entries in different formats, for example due to backwards
compatibility concerns. If they do, they SHOULD also serve entry bundles, and
MUST serve the differently-encoded entries at a different URL from the specified
entry bundle URL.

### Pruning

In some log applications, such as [Certificate Transparency][], entries expire
and are replaced with renewed versions. As this happens, the total size of the
log grows, even if the unexpired subset remains fixed. To mitigate this, a log
MAY be *pruned*. Pruning makes some prefix of the log unavailable, without
changing the tree structure.

Logs maintain a *minimum index* value. The minimum index is the index of the
first log entry that the log publishes. It MUST be less than or equal to the
tree size of the log's current checkpoint. In an unpruned log, the minimum index
is zero.

In response to a request for a full tile `<prefix>/tile/<L>/<N>`, or an entry
bundle `<prefix>/tile/entries/<N>`, the log MAY return a 410 or 404 response if the
resource's end index, defined above, is below or equal to the minimum index.
Logs are RECOMMENDED to implement this by denying HTTP requests, rather than
deleting the resources from storage. This allows the log to easily recover from
misconfiguration if the minimum index was set to too high a value.

An entry is said to be *available* if its index is greater than or equal to the
minimum index. A checkpoint is said to be *available* if its tree size is
greater than the minimum index.

This pruning criteria allows a log client to obtain:

* Any available entry
* The hash value for any available checkpoint
* An inclusion proof for any available entry to any containing checkpoint
* A consistency proof between any two available checkpoints

Pruning is similar to the practice of [temporal sharding][] of logs, except it
does not change the structure of the tree or the identity of the log. This means
all existing proofs remain valid, and existing log clients remain compatible
with the pruned log.

This document defines *how* to prune a log, but not policies around *when* or *if*
a log may be pruned. Log ecosystems that permit pruning SHOULD define retention
policies for how long entries must be available. For example, an ecosystem might
require that entries remain accessible for 6 months after they expire.

If an entry is pruned and historical data is not available, e.g. another copy of
the entries or a trusted summary of expiration dates, it may not be possible to
check if the retention policy has been honored. To mitigate this, log clients
SHOULD be periodically updated with a lower bound on which entries to accept.
This lower bound SHOULD be at least the log's minimum index at the time and MAY
be higher, such as the index of the first available, currently unexpired log
entry.

TODO: Some HTTP endpoint for fetching the minimum index? The semantics would be
something like: serving a minimum index equivalent to returning 404 from the
tiles that would be deleted by the pruning criteria, including when evaluating a
log client's availability policies.

## Acknowledgements

This design is based on the Go Checksum Database developed with Russ Cox and on
the feedback of the Sigsum team and of many individuals in the WebPKI community.

[Certificate Transparency]: https://certificate.transparency.dev/
[RFC 6962]: https://www.rfc-editor.org/rfc/rfc6962.html
[RFC 5246]: https://www.rfc-editor.org/rfc/rfc5246.html
[checkpoint]: https://c2sp.org/tlog-checkpoint
[signed note]: https://c2sp.org/signed-note
[temporal sharding]: https://googlechrome.github.io/CertificateTransparency/log_policy.html#temporal-sharding
