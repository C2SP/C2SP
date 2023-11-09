# Checkpoints

Checkpoints are an interoperable format for signed Markle tree heads, in use in the transparency log ecosystem.

A checkpoint is a [signed note](https://c2sp.org/note) with a precisely structured body, issued and signed by a transparency log to commit to a Merkle tree head at a specified tree size.

## Conventions used in this document

The base64 encoding used throughout is the standard Base 64 encoding specified
in [RFC 4648][], Section 4.

`U+` followed by four hexadecimal characters denotes a Unicode codepoint, to be encoded in UTF-8. `0x` followed by two hexadecimal characters denotes
a byte value in the 0-255 range.

Data structures are defined according to the conventions laid out in Section 4 of [RFC 5246][].

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14][] [RFC 2119][] [RFC 8174][] when, and only when, they appear in all capitals, as shown here.

[RFC 4648]: https://www.rfc-editor.org/rfc/rfc4648.html
[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html
[RFC 5246]: https://www.rfc-editor.org/rfc/rfc5246.html
[RFC 6962]: https://www.rfc-editor.org/rfc/rfc6962.html
[RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032.html

## Format

The body is a sequence of al least three non-empty lines, separated by a newline (U+000A).

1. The first line is the **origin**, a unique identifier for the log identity which issued the checkpoint. Like note key names, it MUST be non-empty, well-formed UTF-8 containing neither Unicode spaces nor plus (U+002B), and it SHOULD be a schema-less URL, such as `example.com/log42`. This is only a recommendation to avoid collisions, and clients MUST NOT assume that the origin is following this format.
2. The second line is the **tree size**, the ASCII decimal representation of the number of leaves in the tree, with no leading zeroes (unless the tree is empty, in which case the tree size is `0`).
3. The third line is the **root hash**, the base64 encoding of the log root hash at the specified tree size.
4. Any following lines are **extension lines**, opaque and optional.

The log’s key name in its signature line SHOULD match the origin line. The log MAY use any note signature algorithm to sign the checkpoint, based on the ecosystem it operates on.

According to the note specification, clients MUST ignore unknown signatures. This allows both log key rotation, and witness co-signatures.

## RFC 6962 TreeHeadSignatures

A checkpoint with an [RFC 6962][] `TreeHeadSignature`-based signature carries the same information as a `/ct/v1/get-sth` API response, in a format compatible with the checkpoint ecosystem.

The key name MUST match the origin line. The key ID is defined as the first four bytes (interpreted in big-endian order) of the SHA-256 hash of the following sequence: the key name, a newline, the signature type identifier byte `0x05`, and the RFC 6962 `LogID` (which in turn is the SHA-256 hash of the log's public key, calculated over the DER encoding of the key represented as SubjectPublicKeyInfo).

The signature is an encoding of the following `RFC6962NoteSignature` structure, which includes the timestamp and signature fields of a `get-sth` response. The timestamp is encoded as part of the note signature both for compatibility and because the time at which the checkpoint was signed is more properly a property of the signature than of the checkpoint. For example, witness co-signatures don’t verify or sign the log’s timestamp, and if 24h pass without new leaves being submitted, the log is expect to re-sign the same checkpoint with a new timestamp, but the checkpoint is logically the same.

```
struct {
	uint64 timestamp;
	TreeHeadSignature signature;
} RFC6962NoteSignature;
```

A checkpoint signed with this algorithm MUST NOT include any extension line.

Unfortunately, a `TreeHeadSignature` does not cover the log’s identity.

We considered and decided against defining the origin line to include the log ID. It would help convey the log ID as part of the checkpoint, and would ensure the witnesses co-sign it, but it would also give the false impression that it is signed by the log key, lose the human-friendliness of recognizable names, and prevent log key rotation with witness-enforced consistency.

Note that a `get-sth` response can be converted to a checkpoint signed with this algorithm and vice-versa without access to the private key.

## Witness co-signature

A witness co-signature is a note signature added to a log-issued checkpoint by a third-party witness to attest that the log respected its append-only requirements.

Semantically, a v1 co-signature defined in this section is a statement that, as of the specified time, the consistent tree head with the largest size the witness has observed for the log identified by that key has the specified hash.

V1 co-signatures use Ed25519 according to [RFC 8032][].

The key ID is defined as the first four bytes (interpreted in big-endian order) of the SHA-256 hash of the following sequence: the key name, a newline, the signature type identifier byte `0x04`, and the 32-byte RFC 8032 encoding of the public key.

The signature is performed over the following message: one line spelling `cosignature/v1`, one line representing the current timestamp in seconds since the UNIX epoch encoded as an ASCII decimal with no leading zeroes and prefixed with the string `time` and a space (`0x20`), followed by the first three lines of the checkpoint body (including the final newline).

The signature is encoded as the following `WitnessCosignature` structure.

```
struct {
	uint64 timestamp;
	opaque signature[64];
} WitnessCosignature;
```
