<p align="center">
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="https://github.com/C2SP/C2SP/assets/1225294/0cd04af2-e84d-4f48-b42e-ed430354e563">
        <source media="(prefers-color-scheme: light)" srcset="https://github.com/C2SP/C2SP/assets/1225294/0f239db0-7100-4bba-8608-bd4dc4134409">
        <img alt="The Sunlight logo, a bench under a tree in stylized black ink, cast against a large yellow sun, with the text Sunlight underneath" width="250" src="https://github.com/C2SP/C2SP/assets/1225294/0f239db0-7100-4bba-8608-bd4dc4134409">
    </picture>
</p>

# The Sunlight CT Logs

https://c2sp.org/sunlight

A Sunlight log is a [Certificate Transparency][] log that implements [RFC
6962][] on the write path (for submission), and an HTTP static asset hierarchy
on the read path (for monitoring).

Aside from the different read API, a Sunlight log is a regular CT log that can
work alongside RFC 6962 logs and that fulfills the same purpose. In particular,
it requires no modification to submitters and TLS clients.

This document specifies the public endpoints of a Sunlight log, and is aimed at
consumers (both readers and writers) of the log. A more comprehensive design
document, which explores the motivating tradeoffs and details an implementation
architecture, is available at https://filippo.io/a-different-CT-log.

## Conventions used in this document

Data structures are defined according to the conventions laid out in Section 3
of [RFC 8446][], and with references to structures defined in [RFC 6962][].

`U+` followed by four hexadecimal characters denotes a Unicode codepoint, to be
encoded in UTF-8. `0x` followed by two hexadecimal characters denotes a byte
value in the 0-255 range. `||` denotes concatenation.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][] [RFC 2119][] [RFC
8174][] when, and only when, they appear in all capitals, as shown here.

[RFC 8446]: https://www.rfc-editor.org/rfc/rfc8446.html
[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html

## Parameters

A Sunlight log is defined by a public key (hashed into a LogID, as per RFC 6962,
Section 3.2), and by two URL prefixes: the *submission prefix* for write APIs
and the *monitoring prefix* for read APIs.

A log MAY use the same value for both the *submission prefix* and the
*monitoring prefix*.

For example, a log with

   * *submission prefix* `https://rome.ct.example.com/2024h1/` and
   * *monitoring prefix* `https://rome2024h1.bucket.example.org/`

will serve API endpoints defined below at

`https://rome.ct.example.com/2024h1/ct/v1/add-chain`

and

`https://rome2024h1.bucket.example.org/checkpoint`

## Submission APIs

For clients submitting certificates, a Sunlight log is fully RFC 6962 compliant:
it implements the RFC 6962 submission APIs and produces RFC 6962 signatures.

In particular, a Sunlight log MUST implement:

   - the `<submission prefix>/ct/v1/add-chain` API endpoint according to
     RFC 6962, Section 4.1
   - the `<submission prefix>/ct/v1/add-pre-chain` API endpoint according to
     RFC 6962, Section 4.2
   - the `<submission prefix>/ct/v1/get-roots` API endpoint according to
     RFC 6962, Section 4.7

The Signed Certificate Timestamp and its signature MUST be calculated according
to RFC 6962, Section 3.2.

### SCT Extension

RFC 6962 specifies no extensions, and current logs produce empty extensions
fields. This document defines a format for the `CtExtensions` type, and one
REQUIRED `SignedCertificateTimestamp` extension for Sunlight logs.

According to RFC 6962, submitters SHALL encode the `extensions` field of
`add-[pre-]chain` responses into serialized `SignedCertificateTimestamp`s and
TLS clients SHALL include that field in the digitally signed message being
verified.

	enum {
		leaf_index(0), (255)
	} ExtensionType;
	
	struct {
		ExtensionType extension_type;
		opaque extension_data<0..2^16-1>;
	} Extension;
	
	Extension CTExtensions<0..2^16-1>;

The `CTExtensions` type (opaque in RFC 6962) MUST be a list of zero or more
`Extension`s, similarly to [RFC 5246][], but with a one-byte `ExtensionType`.
The order of extensions in an extensions field is arbitrary and MUST be ignored.
Duplicate extensions with the same `ExtensionType` MUST NOT be included in the
same extensions field.

	uint8 uint40[5];
	uint40 LeafIndex;

Sunlight logs MUST include a `leaf_index` extension in the `extensions` field of
`SignedCertificateTimestamp`. The `extension_data` field of this extension MUST
be a `LeafIndex` value, which is a big-endian unsigned 40-bit integer specifying
the 0-based index of the included entry in the log.

The total length of an `extensions` field containing only a `leaf_index`
extension is 8 bytes.

Note that by design this encourages a null Merge Delay, since
entries must be sequenced before an SCT is returned, for this extension
to be included.

This extension makes it possible for auditors to verify inclusion of an SCT in
the log by fetching the entry by index, rather than by hash.

## Monitoring APIs

The entries in a Sunlight tree, as well as accessory information such as proofs
and signed tree heads are exposed not through the RFC 6962 dynamic APIs, but as
static assets which can be fetched with HTTP GET requests, and which can be
efficiently cached and compressed.

Note that all cryptographic operations (such as hashes and signatures) are as
specified by RFC 6962, so these APIs can be thought of as an alternative
encoding format for the same data, and operators MAY run a full RFC 6962
interface as a reverse proxy in front of a Sunlight log.

### Checkpoints

The Signed Tree Head is served as a [checkpoint][] at

    <monitoring prefix>/checkpoint

with `Content-Type: text/plain; charset=utf-8`.

This endpoint is mutable, so its headers SHOULD prevent caching beyond a few seconds.

The checkpoint body MUST encode the size and Merkle Tree Hash of the latest
public Signed Tree Head, and the origin line MUST be the submission prefix of
the log as a schema-less URL with no trailing slashes.

For example, a log with *submission prefix* `https://rome.ct.example.com/2024h1/`
will use `rome.ct.example.com/2024h1` as the checkpoint origin line.

The signature and the timestamp are encoded as a [note signature][]. The key
name of the signature line MUST match the checkpoint origin line. The key ID
MUST be the first four bytes (interpreted in big-endian order) of the SHA-256
hash of the following sequence: the key name, a newline character (`0x0A`), the
signature type identifier byte `0x05`, and the 32-byte RFC 6962 `LogID`.

The signature body MUST be an encoding of the following structure.

```
struct {
	uint64 timestamp;
	TreeHeadSignature signature;
} RFC6962NoteSignature;
```

“timestamp” is the `TreeHeadSignature.timestamp` field.

“signature” is the `TreeHeadSignature` digitally-signed value. (Unfortunately, a
`TreeHeadSignature` does not cover the log’s identity, so the origin line is
unauthenticated.)

A checkpoint signed with this algorithm MUST NOT include any extension lines.

Note that a RFC 6962 `get-sth` response can be converted to a checkpoint (with
knowledge of the origin line) and vice-versa without access to the private key.

### Merkle Tree

Instead of serving arbitrary consistency and inclusion proofs, Sunlight logs
serve the Merkle Tree as a set of “tiles”: concatenated sequences of consecutive
Merkle Tree Hashes at a certain tree height. Clients can fetch all the tiles
they need in parallel and compute arbitrary proofs.

Tiles are served as at

    <monitoring prefix>/tile/<L>/<N>[.p/<W>]

with `Content-Type: application/data`.

`<L>` is the “level” of the tile, and MUST be a decimal ASCII integer between 0
and 63, with no additional leading zeroes.

`<N>` is the index of the tile within the level. It MUST be a non-negative
integer encoded into 3-digit path elements. All but the last path element MUST
begin with an `x`. For example, index 1234067 will be encoded as
`x001/x234/067`.

The `.p/<W>` suffix is only present for partial tiles, defined below. `<W>` is
the width of the tile, a decimal ASCII integer between 1 and 255, with no
additional leading zeroes.

This endpoint is immutable, so its caching headers SHOULD be long-lived.

Full tiles MUST be exactly 256 hashes wide, or 8,192 bytes.  At “level 0” tiles
contain leaf hashes. At “level 1” and above, each hash in a tile is the Merkle
Tree Hash of a full tile at the level below.

More formally, in the language of RFC 6962, Section 2.1, the *n*-th tile at
level *l*, with *n* and *l* starting at 0, is the sequence of the following
Merkle Tree Hashes, with *i* from 0 to 255:

	MTH(D[(n * 256 + i) * 256**l : (n * 256 + i + 1) * 256**l])

Note that a tile represents the entire subtree of height 8 with its hashes as
the leaves. The Merkle Tree levels between those expressed by the tile hashes
can be reconstructed by hashing the leaves.

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

Sunlight logs MUST serve partial tiles corresponding to tree sizes for which a
checkpoint was produced, but MAY omit any partial tile for which the
corresponding full tile is available. Clients MUST NOT fetch arbitrary partial
tiles without verifying a checkpoint with a size that requires their existence,
and SHOULD fetch the full tile in parallel as a fallback in case the partial
tile is not available anymore.

### Log entries

The log entries are served as a “data tile” at

    <monitoring prefix>/tile/data/<N>[.p/<W>]

with `Content-Type: application/data`.

Data tiles SHOULD be compressed at the HTTP layer. Logs MAY use
`Content-Encoding: gzip` with no negotiation, or any compression algorithm
requested by the client with `Accept-Encoding`. Clients SHOULD include `gzip`
and `identity` in their `Accept-Encoding` headers.

This endpoint is immutable, so its caching headers SHOULD be long-lived.

The entries in a data tile match the entries in the corresponding “level 0”
tile. Data tiles are sequences of the following structure, one per entry.

```
struct {
	TimestampedEntry timestamped_entry;
	select (entry_type) {
		case x509_entry: Empty;
		case precert_entry: ASN.1Cert pre_certificate;
	};
} TileLeaf;
```

“timestamped_entry” is the `TimestampedEntry` sub-structure of a
`MerkleTreeLeaf` according to RFC 6962, Section 3.4.

“pre_certificate” is the Precertificate submitted for auditing.

### Issuers

The issuers are served at

    <monitoring prefix>/issuer/<fingerprint>

with `Content-Type: application/pkix-cert`.

`<fingerprint>` is the hex-encoded SHA-256 hash of the ASN.1 encoding of the
certificate.

This endpoint is immutable, so its caching headers SHOULD be long-lived.

The response MUST be a single ASN.1-encoded issuing certificate, exactly
matching what was submitted in an accepted client's `add-chain` or
`add-pre-chain` request.

Every issuer (all certificates excluding the final end-entity Certificate or
Precertificate, but including Precertificate Signing Certificates) of every
submitted chain accepted by the log MUST be exposed.

## Acknowledgements

This design is based on the original Certificate Transparency specification, on
the Go Checksum Database developed with Russ Cox, and on the feedback of many
individuals in the WebPKI community, and in particular of the Sigsum, Google
TrustFabric, and ISRG teams.

[Certificate Transparency]: https://certificate.transparency.dev/
[RFC 6962]: https://www.rfc-editor.org/rfc/rfc6962.html
[RFC 5246]: https://www.rfc-editor.org/rfc/rfc5246.html
[checkpoint]: https://c2sp.org/tlog-checkpoint
[note signature]: https://c2sp.org/signed-note
