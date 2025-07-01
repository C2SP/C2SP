# Transparency Log Cosignatures

A cosignature is a statement by some party in a transparency log ecosystem,
such as a [witness][], that it verified the consistency of a [checkpoint][],
along with other properties specified by that cosigner. Log clients can verify a
quorum of cosignatures to prevent split-view attacks and also obtain assurance
of other properties of some log entry.

```
example.com/behind-the-sofa
20852163
CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=

— example.com/behind-the-sofa Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=
— witness.example.com/w1 jWbPPwAAAABkGFDLEZMHwSRaJNiIDoe9DYn/zXcrtPHeolMI5OWXEhZCB9dlrDJsX3b2oyin1nPZ\nqhf5nNo0xUe+mbIUBkBIfZ+qnA==
```

## Conventions used in this document

Data structures are defined according to the conventions laid out in Section 3
of [RFC 8446][].

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
[RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032.html

## Introduction

A **cosigner** is a generalized [witness][]. For each supported log, it follows
some append-only branch of the log, either by being the log operator or by
checking consistency proofs. Along that branch, cosigners will generate
**cosignatures** of checkpoints. A cosignature asserts that some checkpoint is
part of the append-only branch and, optionally, provides additionally
cosigner-specific assertions about the checkpoint.

Cosigners have a **name** and a public key. The name is a unique
identifier for the cosigner. The name MUST be non-empty, and it SHOULD be
a schema-less URL containing neither Unicode spaces nor plus (U+002B), such
as `example.com/mirror42`. This is only a recommendation to avoid collisions,
and clients MUST NOT assume that the name is following this format or that
the URL corresponds to a reachable endpoint.

For example, a [witness][] is a cosigner that provides no guarantees beyond the
append-only assertion. A [mirror][] additionally asserts that the checkpoint's
contents are available from its monitoring interface. Other documents MAY define
cosigner roles that provide other assertions, e.g. checking some [checkpoint][]
extension, or some property of the entries.

When a cosigner signs checkpoints, it is held responsible *both* for upholding
the append-only property *and* for meeting its defined guarantees for all
entries in any checkpoints that it signed.

A single cosigner, with a single cosigner name and public key, MAY generate
cosignatures for checkpoints from multiple logs. The signed message, defined
below, includes both the cosigner name and log origin.

A cosigner's name identifies the cosigner and thus the assertions provided. If
a single operator performs multiple cosigner roles in an ecosystem, each role
MUST use a distinct cosigner name and SHOULD use a distinct key.

## Note Signatures

Concretely, a cosignature is a [note signature][] applied to a
[checkpoint][]. The note signature's key name MUST be the cosigner's name.

Per the signed note format, a note signature line is

    — <name> base64(32-bit key ID || signature)

The key ID is determined from the version of cosignatures being used. Clients
are configured with tuples of (cosigner name, public key, supported cosignature
version) and based on that they can compute the expected name and
key ID, and ignore any signature lines that don't match the name and key ID.

Future cosignature formats MAY reuse the same cosigner public key with a
different key ID algorithm byte (and a different signed message header line).

## V2 Cosignatures

v2 cosignatures are the current cosignature version.

### Format

The key ID for a v2 cosignature MUST be

    SHA-256(<name> || "\n" || 0x06 || 32-byte Ed25519 cosigner public key)[:4]

The signature MUST be a 72-byte `timestamped_signature` structure.

    struct timestamped_signature {
        u64 timestamp;
        u8 signature[64];
    }

"timestamp" is the time at which the cosignature was generated, as seconds since
the UNIX epoch (January 1, 1970 00:00 UTC).

"signature" is an Ed25519 ([RFC 8032][]) signature from the witness public key
over the message defined in the next section.

### Signed message

The signed message MUST be three newline (U+000A) terminated lines (one header
line, one name line, and one timestamp line) followed by the whole note body of
the cosigned checkpoint (including the final newline, but not including any
signature lines).

The header line MUST be the fixed string `cosignature/v2`, and provides domain
separation.

The name line MUST be the cosigner name.

The timestamp line MUST consist of the string `time`, a single space (0x20), and
the number of seconds since the UNIX epoch encoded as an ASCII decimal with no
leading zeroes. This value MUST match the `timestamped_signature.timestamp`.

    cosignature/v2
    witness.example.com/w1
    time 1679315147
    example.com/behind-the-sofa
    20852163
    CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=

Semantically, a v2 cosignature is a statement that, as of the specified time,
the specified checkpoint is of the largest size which:

* has a tree hash which is consistent with all other checkpoints signed by the named cosigner
* satisfies all other properties asserted by the named cosigner

Extension lines MAY be included in the checkpoint by the log, and if present
MUST be included in the cosigned message. However, no semantic statement is made
about any extension line, unless the cosigner is defined to make them.

## V1 Cosignatures

v1 cosignatures are an older, witness-only cosignature version. This version may
only be used by witnesses. It does not carry any additional cosigner guarantees
and additionally does not bind the cosigner name into the signed message.

A witness MAY generate v1 cosignatures using the same key used for v2
cosignatures, however, two distinct witnesses MUST NOT use the same key.

### Format

The key ID for a v1 cosignature MUST be

    SHA-256(<witness name> || "\n" || 0x04 || 32-byte Ed25519 witness public key)[:4]

The signature MUST be a 72-byte `timestamped_signature` structure.

    struct timestamped_signature {
        u64 timestamp;
        u8 signature[64];
    }

"timestamp" is the time at which the cosignature was generated, as seconds since
the UNIX epoch (January 1, 1970 00:00 UTC).

"signature" is an Ed25519 ([RFC 8032][]) signature from the witness public key
over the message defined in the next section.

### Signed message

The signed message MUST be two newline (U+000A) terminated lines (one header
line and one timestamp line) followed by the whole note body of the cosigned
checkpoint (including the final newline, but not including any signature lines).

The header line MUST be the fixed string `cosignature/v1`, and provides domain
separation.

The timestamp line MUST consist of the string `time`, a single space (0x20), and
the number of seconds since the UNIX epoch encoded as an ASCII decimal with no
leading zeroes. This value MUST match the `timestamped_signature.timestamp`.

    cosignature/v1
    time 1679315147
    example.com/behind-the-sofa
    20852163
    CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=

Semantically, a v1 cosignature is a statement that, as of the specified time,
the consistent tree head with the largest size the witness has observed for the
log identified by the origin line has the specified root hash.

Extension lines MAY be included in the checkpoint by the log, and if present
MUST be included in the cosigned message. However, it's important to understand
that the witness is asserting observation of correct append-only operation of
the log based on the first three lines of the checkpoint; no semantic statement
is made about any extension lines, and consensus between witnesses on the
extension lines SHALL NOT be assumed.

[note signature]: https://c2sp.org/signed-note
[mirror]: https://c2sp.org/tlog-mirror
[checkpoint]: https://c2sp.org/tlog-checkpoint
[witness]: https://c2sp.org/tlog-witness
