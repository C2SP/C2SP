# Transparency Log Cosignatures

A cosignature is a statement by a transparency log [witness][] that it verified
the consistency of a [checkpoint][]. Log clients can verify a quorum of
cosignatures to prevent split-view attacks before trusting an inclusion proof.

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

## Format

Concretely, a cosignature is a [note signature][] applied to a [checkpoint][].

Per the signed note format, a note signature line is

    — <key name> base64(32-bit key ID || signature)

The key name SHOULD be a schema-less URL that identifies the witness. Like the
checkpoint origin line, this is for disambiguation, and MAY match a publicly
reachable endpoint or not.

The key ID MUST be

    SHA-256(<name> || "\n" || 0x04 || 32-byte Ed25519 witness public key)[:4]

Clients are configured with tuples of (witness name, public key, supported
cosignature version) and based on that they can compute the expected name and
key ID, and ignore any signature lines that don't match the name and key ID.

Public keys MAY be encoded as [vkeys][] with signature type 0x04 and the 32-byte
Ed25519 witness public key as the public key material.

Future cosignature formats MAY reuse the same witness public key with a
different key ID algorithm byte (and a different signed message header line).

The signature MUST be a 72-byte `timestamped_signature` structure.

    struct timestamped_signature {
        u64 timestamp;
        u8 signature[64];
    }

"timestamp" is the time at which the cosignature was generated, as seconds since
the UNIX epoch (January 1, 1970 00:00 UTC).

"signature" is an Ed25519 ([RFC 8032][]) signature from the witness public key
over the message defined in the next section.

## Signed message

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
[vkeys]: https://c2sp.org/signed-note#verifier-keys
[checkpoint]: https://c2sp.org/tlog-checkpoint
[witness]: https://c2sp.org/tlog-witness
