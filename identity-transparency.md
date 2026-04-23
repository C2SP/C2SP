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
[RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032.html

## Leaf Entry Format

The leaf entry is a sequence of bytes. The leaf entry MUST start with a single
byte version identifier, and MUST be followed by repeated 32-byte SHA-256
digests.

Example leaf entry, where `||` denotes concatenated values.

```
0x01 || Hash(message) || Hash(Root of trust) || Hash(key1) || Hash(value1) || Hash(key2) || Hash(value2) || ... || Hash(keyN) || Hash(valueN)
```

The first byte MUST be the byte `0x01`. Future versions of this leaf format
MUST increment this byte value.

The next 32 bytes MUST be a digest of the `message` submitted to the log.
`message` MUST be the digest of the original data. `message` is hashed again to
prevent log poisoning where entries contain spam, e.g. spam is split into byte
arrays with each chunk uploaded as a message. Logs MUST reject any messages
that are not 32 bytes.

The next 32 bytes MUST be the digest of a root of trust. The root of trust
SHOULD be a public key, for example the signer's public key or a public key
from a root certificate. The encoding of the public key is ecosystem-dependent.

The remainder of the leaf entry is optional.

The following bytes are a key-value mapping of ecosystem-specific strings. A
32-byte digest of a key name MUST be followed by the 32-byte digest of a value.
It is recommended to apply a restriction on the number of key-value pairs to
prevent large leaf entries.

TODO: Should we document why the leaf doesn't contain the signature, and the
(optional?) responsibility by the log operator to persist signatures for
non-repudiation

## Signature Format

For `data` to be signed, the client MUST use `SHA256(data)` as the `message` to
be submitted to the log.

The `signature` is computed over the concatenation of the log entry version
`0x01` (as a domain separator demonstrating the intent to log signed data), the
NUL character `0x00`, and the checksum `SHA256(message)=SHA256(SHA256(data))`.

Any signature algorithm may be used.

## Verification

TODO: Do we need a section on how to verify an entry?
