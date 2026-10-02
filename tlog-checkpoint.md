---
description: Interoperable transparency log signed tree heads
---

> [!WARNING]
> This is the editor's copy of this specification.
> For a stable rendered reference, use [c2sp.org/tlog-checkpoint](https://c2sp.org/tlog-checkpoint).

# Transparency Log Checkpoints

A checkpoint is a [signed note][] where the body is precisely formatted for use
in transparency log applications.  The mandatory note text includes the three
essential parts of a log's Merkle tree head at a given size.

```
example.com/behind-the-sofa
20852163
CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=

— example.com/behind-the-sofa Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=
```

## Conventions used in this document

The base64 encoding used throughout is the standard Base 64 encoding specified
in [RFC 4648][], Section 4, with `=` padding. Encoders MUST generate
canonical base64 according to RFC 4648, Section 3.5, and decoders MUST reject
non-canonical encodings.

`U+` followed by four hexadecimal characters denotes a Unicode codepoint, to be
encoded in UTF-8. `0x` followed by two hexadecimal characters denotes a byte
value in the 0-255 range. `||` denotes concatenation.

A non-negative integer encoded as an ASCII decimal is a string containing the
base-10 representation of the integer with no extra leading zeros. Zero is
encoded as `0`, not the empty string.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][] [RFC 2119][] [RFC
8174][] when, and only when, they appear in all capitals, as shown here.

[RFC 4648]: https://www.rfc-editor.org/rfc/rfc4648.html
[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html
[RFC 6962]: https://www.rfc-editor.org/rfc/rfc6962.html

## Note text

The note text of a checkpoint is a sequence of at least three non-empty lines,
separated by newlines (U+000A).

 1. The first line is the log's **origin**, as defined in [tlog-cosignature][].

 2. The second line is the **tree size**, the number of leaves in the tree
    encoded as an ASCII decimal.

 3. The third line is the **root hash**, the base64 encoding of the root of the
    [RFC 6962][] Merkle hash tree at the specified tree size.

 4. Any following lines are **extension lines**, opaque and OPTIONAL. Extension
    lines, if any, MUST be non-empty. The use of extension lines is NOT
    RECOMMENDED, as they are neither auditable by log monitors, nor signed in
    all signature algorithms.

## Signatures

As a [signed note][], the note text described above is followed by an empty
line, and one or more signature lines.

There MAY be multiple signature lines with the same key name. However,
there MUST NOT be multiple signature lines with both the same key
name and the same key id.

A log or [cosigner][tlog-cosignature] MUST NOT sign any checkpoint which is
inconsistent with any checkpoint it previously signed. Two checkpoints are
inconsistent if they are for the same log, and a consistency proof can't be
constructed from one to the other.

The following note signature algorithms are defined for use with checkpoints.
ML-DSA-44 checkpoint cosignatures SHOULD be used, but applications MAY use any
note signature algorithm based on the ecosystem they operate in. Note that
ML-DSA-44 checkpoint cosignatures don't sign the extension lines, which SHOULD
be empty.

### ML-DSA-44 Checkpoint Cosignatures

An ML-DSA-44 checkpoint cosignature is computed as defined in [tlog-cosignature][],
including the 8-byte timestamp. The signature inputs come from the first three
lines of the checkpoint. Extension lines are ignored and not covered by the
signature. It is represented as a note signature with a key name of the cosigner
name and a key ID of:

    SHA-256(<cosigner name> || "\n" || 0x06 || 1312-byte ML-DSA-44 cosigner public key)[:4]

In client configuration, the public key MAY be encoded as a [vkey][] with
signature type 0x06 and the 1312-byte ML-DSA-44 cosigner public key as the
public key material.

This signature type can be used either by the log to authenticate itself, or by
an arbitrary cosigner role. When the log is authenticating itself, the cosigner
name SHOULD be the log origin.

### Ed25519 Log Signatures

An Ed25519 log signature is computed by [signing the note text with Ed25519][].
This signature type only supports the log itself. The key name SHOULD be the log
origin.

Note that, unlike the other signature types usable with checkpoints, Ed25519 log
signatures do not include a timestamp.

### Ed25519 Checkpoint Cosignatures

An Ed25519 checkpoint cosignature is computed as defined in [tlog-cosignature][],
including the 8-byte timestamp. The signature inputs come from the checkpoint.
Extension lines from the checkpoint MUST be included in the signature
computation. Note that the input message to Ed25519 aligns with the note text
format above.

The cosignature is represented as a note signature with a key name of the
cosigner name and a key ID of:

    SHA-256(<cosigner name> || "\n" || 0x04 || 32-byte Ed25519 cosigner public key)[:4]

In client configuration, the public key MAY be encoded as a [vkey][] with
signature type 0x04 and the 32-byte Ed25519 cosigner public key as the
public key material.

This signature type SHOULD only be used by non-log cosigners. If using Ed25519,
the log itself SHOULD use Ed25519 log signatures, defined above.

[tlog-cosignature]: https://c2sp.org/tlog-cosignature
[signed note]: https://c2sp.org/signed-note@v1.0.0
[signing the note text with Ed25519]: https://c2sp.org/signed-note@v1.0.0#ed25519-signatures
[vkey]: https://c2sp.org/signed-note@v1.0.0#verifier-keys
