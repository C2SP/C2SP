# Transparency Log Cosignatures

A cosignature is a statement by a *cosigner* that it verified
the consistency of a [checkpoint][] or [subtree][]. Log clients can verify a quorum of
cosignatures to prevent split-view attacks before trusting an inclusion proof.
A cosigner may make additional statements relating to a checkpoint.  Log clients
that know about this can then be assured of additional cosigning properties.

Below is an example of a checkpoint that contains a cosignature.

```
example.com/behind-the-sofa
20852163
CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=

— example.com/behind-the-sofa Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=
— witness.example.com/w1 jWbPPwAAAABkGFDLEZMHwSRaJNiIDoe9DYn/zXcrtPHeolMI5OWXEhZCB9dlrDJsX3b2oyin1nPZqhf5nNo0xUe+mbIUBkBIfZ+qnA==
```

This document specifies two cosignature types: one based on Ed25519, and one
based on ML-DSA-44. The ML-DSA version SHOULD be used for new deployments.

Unlike the Ed25519 type, the ML-DSA-44 type is secure against quantum computers.
Moreover, it commits to the cosigner's name, and supports signing [subtrees][]
in addition to [checkpoints][checkpoint]. The ML-DSA-44 parameter set was
selected because at NIST Level 2 it provides some margin beyond the 128-bit
security level.

## Conventions used in this document

Data structures are defined according to the conventions laid out in Section 3
of [RFC 8446][].

`U+` followed by four hexadecimal characters denotes a Unicode codepoint, to be
encoded in UTF-8. `0x` followed by two hexadecimal characters denotes a byte
value in the 0-255 range. `||` denotes concatenation.

A time represented as a POSIX timestamp is the time converted to
[seconds since the Epoch][], as defined by [POSIX.1-2024][].

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][] [RFC 2119][] [RFC
8174][] when, and only when, they appear in all capitals, as shown here.

[RFC 8446]: https://www.rfc-editor.org/rfc/rfc8446.html
[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html
[RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032.html
[seconds since the Epoch]: https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html#tag_04_19
[POSIX.1-2024]: https://pubs.opengroup.org/onlinepubs/9799919799

## Format

Concretely, a cosignature is a [note signature][] applied to a [checkpoint][].

Per the signed note format, a note signature line is

    — <key name> base64(32-bit key ID || signature)

The key name SHOULD be a schema-less URL that identifies the cosigner. Like the
checkpoint origin line, this is for disambiguation, and MAY match a publicly
reachable endpoint or not. For ecosystems that use OIDs for identification, the
key name MAY be the string `oid/` followed by an OID in dotted decimal form.

The key ID for Ed25519 cosignatures MUST be computed as

    SHA-256(<name> || "\n" || 0x04 || 32-byte Ed25519 cosigner public key)[:4]

The key ID for ML-DSA-44 cosignatures MUST be computed as

    SHA-256(<name> || "\n" || 0x06 || 1312-byte ML-DSA-44 cosigner public key)[:4]

Clients are configured with tuples of (cosigner name, public key, supported
cosignature version) and based on that they can compute the expected name and
key ID, and ignore any signature lines that don't match the name and key ID.

Ed25519 public keys MAY be encoded as [vkeys][] with signature type 0x04 and the
32-byte Ed25519 cosigner public key as the public key material.

ML-DSA-44 public keys MAY be encoded as [vkeys][] with signature type 0x06 and the
1312-byte ML-DSA-44 cosigner public key as the public key material.

Future cosignature formats MAY reuse the same cosigner public key with a
different key ID algorithm byte (and a different newline-terminated prefix).

The signature MUST be a `timestamped_signature` structure.

    struct {
        u64 timestamp;
        select (signature_algorithm) {
            case ed25519: opaque ed25519_signature[64];
            case ml-dsa-44: opaque ml_dsa_44_signature[2420];
        } signature;
    } timestamped_signature;

`timestamp` is the time at which the cosignature was generated, as a POSIX
timestamp.  It MUST NOT exceed 2^63 - 1, and verifiers MAY reject cosignatures
with timestamps in the future.

`signature` is an Ed25519 ([RFC 8032][]) or ML-DSA-44 ([FIPS 204][]) signature
from the cosigner public key over the message defined below.

Per [RFC 8446][], Section 3.3, these are serialized in sequence, with the
timestamp encoded in big-endian order.

## Ed25519 signed message

The signed message MUST be two newline (U+000A) terminated lines (one header
line and one timestamp line) followed by the whole note body of the cosigned
checkpoint (including the final newline, but not including any signature lines).

The header line MUST be the fixed string `cosignature/v1`, and provides domain
separation.

The timestamp line MUST consist of the string `time`, a single space (0x20), and
`timestamped_signature.timestamp` encoded as an ASCII decimal with no leading
zeroes.

    cosignature/v1
    time 1679315147
    example.com/behind-the-sofa
    20852163
    CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=

Semantically, a v1 cosignature is a statement that, as of the specified time,
the consistent tree head with the largest size the cosigner has observed for the
log identified by the origin line has the specified root hash.

Extension lines MAY be included in the checkpoint by the log, and if present
MUST be included in the cosigned message. However, it's important to understand
that the cosigner is asserting observation of correct append-only operation of
the log based on the first three lines of the checkpoint; consensus between
cosigners on the extension lines SHALL NOT be assumed, and no semantic statement
is made about any extension lines unless the cosigner's operator says otherwise.

A cosigner operator that operates multiple Ed25519 cosigners (e.g. with distinct
additional statements, see below) MUST use distinct public keys for each
cosigner. The Ed25519 signed message format doesn't commit to the cosigner name,
so the same public key can't be used across multiple cosigners.

## ML-DSA-44 signed message

The signed message MUST be a `cosigned_message` structure.

    struct {
        uint8 label[12] = "subtree/v1\n\0";
        opaque cosigner_name<1..2^8-1>;
        uint64 timestamp;
        opaque log_origin<1..2^8-1>;
        uint64 start;
        uint64 end;
        uint8 hash[32];
    } cosigned_message;

`cosigner_name` is the cosigner name.

`timestamp` is `timestamped_signature.timestamp`. These two values MAY be zero
if the cosigner doesn't make any statement as to the tree being the largest
observed at time of signing. If `start` is not zero, these values MUST be zero.

`log_origin` is the log's origin, as represented in a checkpoint's origin line
without the final newline.

`start` is the index of the first leaf included in the [subtree][] being signed.
If signing a [checkpoint][], it MUST be zero. If `start` is not zero,
`timestamp` MUST be zero.

`end` is the exclusive upper bound of the indexes of the leaves in the
[subtree][] being signed: the index of the last included leaf plus one. If
signing a [checkpoint][], it is the size of the tree.

`hash` is the root hash of the subtree being signed.

Semantically, a v1 subtree cosignature is a statement that the subtree with the
specified root hash is consistent with all other historical views observed by
the cosigner of the log identified by the origin line. If the timestamp is not
zero, it is also a statement that, as of the specified time, this is the largest
consistent tree the cosigner has observed for the log.

Note that checkpoint extension lines are not included in the signed message for
ML-DSA-44 cosignatures, and no statement is made about them. Subtrees with
non-zero start values currently don't have a checkpoint representation.

## Additional statements

A cosigner MAY make additional statements about a checkpoint.  These
additional statements need to be communicated out of band to those defining
trust policies based on tuples of (public key, supported cosignature version).
A given tuple MUST imply a single set of statements.  These statements MUST
include the base cosignature semantics, and MAY include other statements that
are non-conflicting.  Examples of non-conflicting statements include "I also
mirrored the log up until the checkpoint size" and "I certify the SAN ←→ public
key associations in the log leaves".  See [tlog-mirror][] for an example.

[note signature]: https://c2sp.org/signed-note@v1.0.0
[vkeys]: https://c2sp.org/signed-note@v1.0.0#verifier-keys
[checkpoint]: https://c2sp.org/tlog-checkpoint@v1.0.0
[tlog-mirror]: https://c2sp.org/tlog-mirror
[FIPS 204]: https://csrc.nist.gov/pubs/fips/204/final
[subtree]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-02.html#name-subtrees
