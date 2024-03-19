# Note

A note is text signed by one or more keys.

The text MUST be ignored unless the note is signed by a trusted key and the
signature has been verified. This makes notes well-suited for artifacts that are
only exposed to technical operators, and not for user-facing purposes (such as
email).

```
Ognuno sta solo sul cuor della terra
trafitto da un raggio di sole:

ed è subito sera.

— quasimodo.example/salvatore NnugSzTjtVAewIS+Z/iJhUPeFDkO/5QQ2i5ddnGITLlC+EhfLW9oJKONrMouFSQU0xMcXxj99ihAQwaqP3ZekRwNtIc=
```

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
[RFC 8032]: https://www.rfc-editor.org/rfc/rfc8032.html

## Format

A signed note consists of a text ending in newline (U+000A), followed by a blank
line (only a newline), followed by one or more signature lines of this form: em
dash (U+2014), space (U+0020), key name, space, base64-encoded signature,
newline.

Signed notes MUST be valid UTF-8 and MUST NOT contain any ASCII control
characters (those below U+0020) other than newline.

The note text includes the final newline but not the separating blank line. The
note text MAY contain empty lines; the text is separated from the signatures by
the last empty line in the note.

Key names MUST be non-empty and MUST NOT contain any Unicode spaces or plus
(U+002B) characters.

Signatures are the base64 encoding of 4+n bytes. The first four bytes in the
signature are the uint32 key ID stored in big-endian order. The remaining n
bytes are the result of using the specified key to sign the note text, according
to the signature algorithm.

Verifiers SHOULD apply a maximum limit to the number of signatures in a note
(or, equivalently, to the overall size of a note), but MUST accept at least up
to 16 signatures. Remember that post-quantum signatures can be up to nearly 5kB
in size.

## Signatures

    — <key name> base64(32-bit key ID || signature)

The tuple of key name and key ID uniquely identifies the key that performed the
signature and the algorithm it used. Verifiers MUST ignore signatures from
unknown keys, even if they share a name or ID (but not both) with a known key.
If the key name and ID match a known key, verifiers MUST verify the signature.
If a signature from a known key fails to verify, clients MAY reject the whole
note. If no signature from a known key verifies successfully, clients MUST
reject the note.

Note that the key ID is intentionally short, as it is an identifier, and not a
cryptographically strong hash. An attacker can easily compute a public key that
will collide a target key hash, but all they will get is a signature
verification failure, because the client was necessarily securely configured
with the expected public key for the key hash.

It is RECOMMENDED that key names be schema-less URLs (e.g. `example.com/abc123`),
to avoid accidental collisions. Those endpoints don’t need to be reachable over
the network.

It is RECOMMENDED that key IDs be the first four bytes (interpreted in
big-endian order) of the SHA-256 hash of the following sequence: the key name, a
newline, a single signature type identifier byte assigned below, and the
encoding of the public key. Note that this allows reusing the same cryptographic
key and name for different signature types without ambiguity, if necessary (and
if domain separation can be ensured).

    key ID = SHA-256(key name || 0x0A || signature type || public key)[:4]

Accidental collisions of *both* key name and key ID can lead to errors if
signatures from colliding keys pairs are applied to the same note. The
recommendations above make such collisions exceedingly unlikely.

### Signature types

The following are the assigned signature type identifier bytes. Other
specifications may define the format and semantics of these signature types, and
they MAY require specific content structures of the note text.

Although multiple signature types are specified, implementations SHOULD select
only the one(s) required for their design, and avoid supporting multiple ones at
runtime if possible.

* `0x01` — Ed25519 signatures as specified by this document.

* `0x02` — ECDSA signatures as implemented by github.com/transparency-dev/witness.

  * The ECDSA curve MUST be one of NIST P-256, NIST P-384, or NIST P-521, and
    SHOULD be NIST P-256.

  * Note that the key ID for these signatures is the truncated SHA-256 hash of
    the DER encoded public key in SPKI format.

* `0x03` — Reserved.

* `0x04` — Timestamped Ed25519 witness cosignatures, as specified by
  c2sp.org/tlog-cosignature.

* `0x05` — RFC 6962 `TreeHeadSignature`s, as specified by c2sp.org/sunlight.

* `0xfa`–`0xfe` — Reserved for future use.

* `0xff` — Reserved for signature types without an identifier byte assigned by
  this specification. It is RECOMMENDED that this byte be followed by a longer
  identifier that is unlikely to collide.

### Ed25519 signatures

Ed25519 signatures are generated according to [RFC 8032][] over the note text.

The key ID is generated as recommended above, with the public key encoded as 32
bytes according to RFC 8032 and signature type identifier byte `0x01`.

    key ID = SHA-256(key name || 0x0A || 0x01 || 32-byte Ed25519 public key)[:4]
