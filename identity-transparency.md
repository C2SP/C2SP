# Identity-based Transparency Logging Spec

TODO: Add section on background and motivation, including:

* Background on existing solutions, with an opportunity to share tooling and have redundant log operators
* Minimizing the entry size, especially given ML-DSA's large public key and signature size
* Removing log poisoning risk
* Providing ecosystem-specific context strings

## Conventions used in this document

The base64 encoding used throughout is the standard Base 64 encoding specified
in [RFC 4648][], Section 4. The hex encoding of a positive integer is the fixed
length lowercase Base 16 encoding of its zero-padded big endian representation.

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
[RFC 8410]: https://www.rfc-editor.org/rfc/rfc8410.html
[RFC 9881]: https://www.rfc-editor.org/rfc/rfc9881.html

## Leaf Entry Format

The leaf entry is a sequence of bytes. The leaf entry MUST start with a single
byte version identifier.

### Version 0x01

Example leaf entry, where `||` denotes concatenated values and `...` denotes
repeated values:

```text
0x01 ||
Hash(root of trust) ||
Hash(message) ||
Hash(Hash(key1)) || Hash(Hash(value1)) ||
Hash(Hash(key2)) || Hash(Hash(value2)) ||
... ||
Hash(Hash(keyN)) || Hash(Hash(valueN)) ||
H(receipt)
```

The first byte MUST be the byte `0x01`. Future versions of this leaf format
MUST increment this byte value.

The next 32 bytes MUST be a digest of the `message` submitted to the log.
`message` MUST be the digest of the original data. `message` is hashed again to
prevent log poisoning where entries contain unwanted bytes, e.g. meaningful
content is split into byte arrays with each chunk uploaded as a message. Logs
MUST reject any messages that are not 32 bytes.

The next 32 bytes MUST be the digest of a root of trust. The root of trust
SHOULD be a public key, for example the signer's public key or a public key
from a root certificate. The encoding of the public key is ecosystem-dependent.

The following bytes are a key-value mapping of ecosystem-specific strings. A
32-byte digest of the digest of a key name MUST be followed by the 32-byte
digest of the digest of a value. The key-value strings are double-hashed to
allow the log to accept either the key/value, or the digest of the key/value
if the key or value is large or should not be revealed to the log.
It is recommended to apply a restriction on the number of key-value pairs to
prevent large leaf entries.
Key/value pairs MUST be sorted lexicographically by the double-digest of the
key.

The last 32 bytes MUST be the digest of a _receipt_. The receipt provides
non-repudiation for the log operator, proving the log received a valid
_credential_ to upload to the log. The receipt MUST be stored outside of the
entry bundle, due to its size. The log MAY NOT generate or the receipt, and in
this case, the 32 bytes MUST only be NUL characters `0x00`. The log MAY set a
time limit on how long a receipt is retained.

## Signature Format

For `data` to be signed, the client MUST use `H(data)` as the `message` to
be submitted to the log, where `H` is `SHA-256`.

The `signature` is computed over the concatenation of the specification
identifier `c2sp.org/identity-transparency/v1` (as a domain seperator
demonstrating the intent to log signed data), the NUL character `0x00`,
the checksum `H(message)=H(H(data))`, and the ecosystem-specific
context strings
`H(H(key1))||H(H(value1))||...||H(H(keyN))||H(H(valueN))`.

The signature algorithm MUST be one of the following:

* ML-DSA-44
* Ed25519

## Root of Trust & Receipt

The root of trust and receipt depends on the _credential_ submitted to the log
to demonstrate ownership of an identity. Additional credentials may be added
in future revisions.

### Credential: Public Key

The `root of trust` is the PKIX ASN.1 `SubjectPublicKeyInfo` as per [RFC 8410][]
and [RFC 9881][] for Ed25519 and ML-DSA respectively. The `root of trust` MUST
be prefixed by a signature algorithm identifier, either:

* `ML-DSA-44`
* `Ed25519`

The `receipt` is the signature, whose encoding is defined in [RFC 8410][] and
[RFC 9881][].

### Credential: OpenID Connect Identity Token

The `root of trust` is the issuer of the token, as a string. The value SHOULD
come from the `iss` JWT claim or MAY come from a specified claim populated by a
federated issuer.

The receipt is a zero-knowledge proof over the token signature.

## Context Key-Value Pairs

TODO: Add Sigsum context string

TODO: Populate from [Sigstore OIDs](https://github.com/sigstore/fulcio/blob/main/docs/oid-info.md#directory)

## Verification

TODO: Do we need a section on how to verify an entry?
