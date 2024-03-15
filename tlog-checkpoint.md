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

[signed note]: https://c2sp.org/signed-note

## Conventions used in this document

The base64 encoding used throughout is the standard Base 64 encoding specified
in [RFC 4648][], Section 4.

`U+` followed by four hexadecimal characters denotes a Unicode codepoint, to be
encoded in UTF-8. `0x` followed by two hexadecimal characters denotes a byte
value in the 0-255 range. `||` denotes concatenation.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][] [RFC 2119][] [RFC
8174][] when, and only when, they appear in all capitals, as shown here.

[RFC 4648]: https://www.rfc-editor.org/rfc/rfc4648.html
[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html
[RFC 5246]: https://www.rfc-editor.org/rfc/rfc5246.html
[RFC 6962]: https://www.rfc-editor.org/rfc/rfc6962.html
[RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032.html

## Note text

The note text is a sequence of at least three non-empty lines, separated by
newlines (U+000A).

 1. The first line is the **origin**, a unique identifier for the log identity
    which issued the checkpoint. The origin MUST be non-empty, and it SHOULD be
    a schema-less URL containing neither Unicode spaces nor plus (U+002B), such
    as `example.com/log42`. This is only a recommendation to avoid collisions,
    and clients MUST NOT assume that the origin is following this format or that
    the URL corresponds to a reachable endpoint.

 2. The second line is the **tree size**, the ASCII decimal representation of
    the number of leaves in the tree, with no leading zeroes (unless the tree is
    empty, in which case the tree size is `0`).

 3. The third line is the **root hash**, the base64 encoding of the root of the
    [RFC 6962] Merkle hash tree at the specified tree size.

 4. Any following lines are **extension lines**, opaque and OPTIONAL. Extension
    lines, if any, MUST be non-empty. The use of extension lines is NOT
    RECOMMENDED, as they are not auditable by log monitors.

## Signatures

Logs MUST not sign any checkpoint which is inconsistent with any checkpoint it
previously signed. Two checkpoints are inconsistent if a consistency proof can't
be constructed from one to the other.

The log’s key name in its signature line SHOULD match the origin line.

Logs SHOULD use Ed25519 signatures to sign the checkpoint, but MAY use any note
signature algorithm based on the ecosystem they operate in.

According to the note specification, clients MUST ignore unknown signatures.
This enables, for example, log key rotation, and witness cosigning.
