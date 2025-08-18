# age

[c2sp.org/age](https://c2sp.org/age),
[age-encryption.org/v1](https://age-encryption.org/v1)

age is a modern file encryption format with multiple pluggable recipients, and
seekable streaming encryption.

## Conventions used in this document

ABNF syntax follows [RFC 5234][] and [RFC 7405][] and references the core rules
in RFC 5234, Appendix B.1.

The base64 encoding used throughout is the standard Base 64 encoding specified
in [RFC 4648][], Section 4, without `=` padding characters (sometimes referred
to as "raw" or "unpadded" base64). Encoders MUST generate canonical base64
according to RFC 4648, Section 3.5, and decoders MUST reject non-canonical
encodings and encodings ending with `=` padding characters.

Keys derived with HKDF-SHA-256 are produced by applying HKDF-Extract with the
specified salt followed by HKDF-Expand with the specified info according to
[RFC 5869][]. The hash used with HKDF in this specification is always SHA-256.
The length of the output keying material is always 32 bytes.

ChaCha20-Poly1305 is the AEAD encryption function from [RFC 7539][].

`||` denotes concatenation. `0x` followed by two hexadecimal characters denotes
a byte value in the 0-255 range. `[:N]` denotes truncation to the first N
bytes of a byte string.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][] [RFC 2119][]
[RFC 8174][] when, and only when, they appear in all capitals, as shown here.

## Encrypted file format

An age file is composed of two parts: a textual [header](#header) that carries
the _file key_, and a binary [payload](#payload) encrypted with it. Overall, age
files MUST be treated as binary, and are not malleable without knowledge of the
file key.

age files MAY use the extension `.age`, in both their binary and
[armored](#ascii-armor) formats.

### File key

Each file is encrypted with a 128-bit symmetric _file key_.

The _file key_ MUST be generated as 16 bytes of CSPRNG output. It MUST NOT be
reused across multiple files.

### Header

The textual file header wraps the _file key_ for one or more _recipients_, so
that it can be unwrapped by one of the corresponding _identities_. It starts with a
version line, followed by one or more recipient stanzas, and ends with a MAC.

    age-encryption.org/v1
    -> X25519 XEl0dJ6y3C7KZkgmgWUicg63EyXJiwBJW8PdYJ/cYBE
    qRS0AMjdjPvZ/WT08U2KL4G+PIooA3hy38SvLpvaC1E
    --- HK2NmOBN9Dpq0Gw6xMCuhFcQlQLvZ/wQUi/2scLG75s

Note that each section of the header can be parsed by looking at its first three
characters, and it ends either at the next newline (for version and MAC lines)
or at the first line shorter than 64 columns (for stanzas).

#### Version line

The version line always starts with "age-encryption.org/", is followed by an
arbitrary version string, and ends with a line feed (`0x0A`).

    version-line = %s"age-encryption.org/" version LF

    version = 1*VCHAR

This document only specifies the `v1` format. Anything after the end of the
version line may change in future versions.

#### Recipient stanza

A recipient stanza starts with `->`, followed after a space by one or more space-separated
arguments, and a base64-encoded body wrapped at 64 columns. The body MUST end
with a line shorter than 64 characters, which MAY be empty.

Each recipient stanza wraps the same _file key_ independently. Identity
implementations are provided the full set of stanzas and recognize those
addressed to them from their arguments. Identity implementations MUST ignore
unrecognized stanzas, unless they wish to require that the recipient type they
implement is not mixed with other types.

It is RECOMMENDED that non-native recipient implementations use fully-qualified
names as the first stanza argument, such as `example.com/enigma`, to avoid
ambiguity and conflicts.

Recipient implementations MAY choose to include an identifier of the specific
recipient (for example, a short hash of the public key) as an argument. Note
that this sacrifices any chance of ciphertext anonymity and unlinkability.

#### Header MAC

The final header line starts with `---` and is followed after a space by the
base64-encoded MAC of the header. The MAC is computed with HMAC-SHA-256 (see
[RFC 2104][]) over the whole header up to and including the `---` mark
(excluding the space following it).

The HMAC key is computed as follows:

    HMAC key = HKDF-SHA-256(ikm = file key, salt = empty, info = "header")

#### ABNF definition of file header

The following is the ABNF definition of the v1 file header.

    header = v1-line 1*stanza end

    v1-line = %s"age-encryption.org/v1" LF

    end = "--- " 43base64char LF

    base64char = ALPHA / DIGIT / "+" / "/"

    stanza = arg-line *full-line final-line

    arg-line = "-> " argument *(SP argument) LF

    argument = 1*VCHAR

    full-line = 64base64char LF

    final-line = *63base64char LF

### Payload

The binary payload encrypts the file body and starts immediately after the
header. It begins with a 16-byte nonce generated by the sender from a CSPRNG.
A new nonce MUST be generated for each file.

The payload key is computed as follows:

    payload key = HKDF-SHA-256(ikm = file key, salt = nonce, info = "payload")

The payload is split in chunks of 64 KiB, and each of them is encrypted with
ChaCha20-Poly1305, using the payload key and a 12-byte nonce composed as
follows: the first 11 bytes are a big endian chunk counter starting at zero and
incrementing by one for each subsequent chunk; the last byte is 0x01 for the
final chunk and 0x00 for all preceding ones. The final chunk MAY be shorter than
64 KiB but MUST NOT be empty unless the whole payload is empty.

This is a STREAM variant from [Online Authenticated-Encryption and its
Nonce-Reuse Misuse-Resistance][STREAM]. It is similar to those used by [Tink][]
and [Miscreant][], but it doesn't prefix the AEAD nonce with key material as the
payload key is 256 bits (enough even to provide a security margin in the
multi-target setting) and derived from both file key and nonce.

The payload can be streamed by decrypting or encrypting one chunk at a time.
Streaming decryption MUST signal an error if the end of file is reached without
successfully decrypting a final chunk.

The payload can be seeked by jumping ahead in chunk increments, and decrypting
the whole chunk that contains the seeked position. Seeking relatively to the end
of file MUST first decrypt and verify that the last chunk is a valid final
chunk.

The payload MUST NOT be modified without re-encrypting it as a new file with a
fresh nonce.

## Native recipient types

This document specifies four native age recipient types: an asymmetric
encryption type based on X25519, a passphrase encryption type based on scrypt,
and two tagged recipient types based on P-256 ECDH and ML-KEM for hardware keys.

### The X25519 recipient type

An X25519 identity is generated as

    identity = read(CSPRNG, 32)

and encoded as [Bech32][] with HRP `AGE-SECRET-KEY-`.

    AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX

The corresponding recipient is computed as

    recipient = X25519(identity, basepoint)

where `X25519` is from [RFC 7748][], Section 5, and `basepoint` is the
Curve25519 base point from RFC 7748, Section 4.1.

The recipient is encoded as Bech32 with HRP `age`.

    age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj

Note that Bech32 strings can only be all uppercase or all lowercase, but the
checksum is always computed over the lowercase string.

#### X25519 recipient stanza

An X25519 recipient stanza has two arguments.

    -> X25519 O6DLx/wDIawpUC978NSPjYvrfDtJVnZApXKp4FMPHCY
    3aKjozt9agh7jGmvOKvR4iax41Wl4zj95MKK4X9JuWc

The first is the fixed string `X25519` and the second is the base64-encoded
ephemeral share computed by the recipient implementation as follows:

    ephemeral secret = read(CSPRNG, 32)
    ephemeral share = X25519(ephemeral secret, basepoint)

A new ephemeral secret MUST be generated for each stanza and each file.

The body of the recipient stanza is computed by the recipient implementation as

    salt = ephemeral share || recipient
    info = "age-encryption.org/v1/X25519"
    shared secret = X25519(ephemeral secret, recipient)
    wrap key = HKDF-SHA-256(ikm = shared secret, salt, info)
    body = ChaCha20-Poly1305(key = wrap key, plaintext = file key)

where the ChaCha20-Poly1305 nonce is fixed as 12 0x00 bytes.

The identity implementation MUST ignore any stanza that does not have `X25519`
as the first argument, and MUST otherwise reject any stanza that has more or
less than two arguments, or where the second argument is not a canonical
encoding of a 32-byte value. It MUST check that the body length is exactly 32
bytes before attempting to decrypt it.

The identity implementation computes the shared secret as follows:

    shared secret = X25519(identity, ephemeral share)

If the shared secret is all 0x00 bytes, the identity implementation MUST abort.

Finally, it derives the key as above and decrypts the file key in the body.

### The scrypt recipient type

The scrypt recipient and identity implementations encrypt and decrypt the file
key with a provided passphrase.

#### scrypt recipient stanza

An scrypt recipient stanza has three arguments.

    -> scrypt ajMFur+EJLGaohv/dLRGnw 18
    8SHBz/ldWnjyGFQqfjat6uNBarWqqEMDS7W8X7+Xq5Q

The first is the string `scrypt`, the second is a base64-encoded salt computed
by the recipient implementation as 16 bytes from a CSPRNG, and the third is the
base-two logarithm of the scrypt work factor in decimal.

A new salt MUST be generated for each stanza and each file.

The body is computed as

    wrap key = scrypt(N = work factor, r = 8, p = 1, dkLen = 32,
        S = "age-encryption.org/v1/scrypt" || salt, P = passphrase)
    body = ChaCha20-Poly1305(key = wrap key, plaintext = file key)

where the ChaCha20-Poly1305 nonce is fixed as 12 0x00 bytes and scrypt is from
[RFC 7914][].

The identity implementation MUST reject any scrypt stanza that has more or less
than three arguments, where the second argument is not a canonical encoding of a
16-byte value, or where the third argument is not a decimal number composed of
only digits with no leading zeroes (`%x31-39 *DIGIT` in ABNF or `^[1-9][0-9]*$`
in regular expression). The identity implementation SHOULD apply an upper limit
to the work factor, and it MUST check that the body length is exactly 32 bytes
before attempting to decrypt it.

An scrypt stanza, if present, MUST be the only stanza in the header. In other
words, scrypt stanzas MAY NOT be mixed with other scrypt stanzas or stanzas of
other types. This is to uphold an expectation of authentication that is
implicit in password-based encryption. The identity implementation MUST reject
headers where an scrypt stanza is present alongside any other stanza.

### The tagged recipient types

The tagged recipient types are designed for hardware keys, where decryption
potentially requires user presence. With knowledge of the public key, it is
possible to check if a stanza was addressed to a specific recipient before
attempting decryption. (This offers less privacy than the default recipient
types.) The tagged recipient types are based on HPKE, and use P-256 ECDH for
compatiblity with existing hardware, optionally hybridized with ML-KEM-786
for quantum resistance.

This document only defines the recipient encodings, and does not define how the
corresponding identities are generated or encoded. We expect these recipients to
be used as the public side of hardware-specific plugin identities.

The non-hybrid recipient is a P-256 curve point serialized as 33 bytes with the
*compressed* Elliptic-Curve-Point-to-Octet-String conversion from [SEC 1, Ver.
2][] and encoded as Bech32 with HRP `age1tag`.

    age1tag1...

The hybrid recipient is a compressed P-256 curve point concatenated with a
ML-KEM-768 encapsulation key, for a total of 1217 bytes, and encoded as Bech32
with HRP `age1tagpq`.

    age1tagpq1...

Note that the P-256 recipient is encoded as a compressed point, unlike the HPKE
SerializePublicKey and DeserializePublicKey functions from [RFC 9180][].

The recipient encodings can be interpreted as plugin recipients with names `tag`
or `tagpq`, allowing for backwards compatibility with existing clients through
plugins.

#### p256tag recipient stanza

To produce a p256tag recipient stanza, the file key is encrypted with the HPKE
SealBase function from [RFC 9180, Section 6.1][], with the following parameters:

  * KEM: DHKEM(P-256, HKDF-SHA256)
  * KDF: HKDF-SHA256
  * AEAD: ChaCha20Poly1305
  * `info = "age-encryption.org/p256tag"`
  * `aad = ""` (empty)

It is then encoded as a recipient stanza with three arguments: the first is the
fixed string `p256tag`, the second is the base64-encoded tag, and the third is
the base64-encoded encapsulated key *enc* from SealBase.

    tag = HKDF-Extract-SHA-256(ikm = enc || pkRm, salt = "age-encryption.org/p256tag")[:4]

Note that the ikm of the tag computation matches the kem_context of the HPKE
Encap and Decap functions.

The body of the recipient stanza is the HPKE ciphertext from SealBase.

    -> p256tag ...
    ...

The identity implementations MUST ignore any stanza that does not have `p256tag`
as the first argument, and MUST otherwise reject any stanza that has more or
less than three arguments, or where the second argument is not a canonical
encoding of a 65-byte value or the third argument is not a canonical encoding of
a 4-byte value. It MUST check that the body length is exactly 32 bytes before
attempting to decrypt it.

#### p256mlkem768tag recipient stanza

To produce a p256mlkem768tag recipient stanza, the file key is encrypted with
the HPKE SealBase function from [RFC 9180, Section 6.1][] with the following
parameters:

  * KEM: QSF-P256-MLKEM768-SHAKE256-SHA3256 from [draft-ietf-hpke-pq-01][] with
    the changes to draft-irtf-cfrg-hybrid-kems in cfrg/draft-irtf-cfrg-hybrid-kems#70
  * KDF: HKDF-SHA256
  * AEAD: ChaCha20Poly1305
  * `info = "age-encryption.org/p256mlkem768tag"`
  * `aad = ""` (empty)

It is then encoded as a recipient stanza with three arguments: the first is the
fixed string `p256mlkem768tag`, the second is the base64-encoded tag, and the
third is the base64-encoded encapsulated key *enc* from SealBase.

    tag = HKDF-Extract-SHA-256(ikm = enc[:65] || pkRm[:65], salt = "age-encryption.org/p256mlkem768tag")[:4]

Note that the ikm of the tag computation only includes the P-256 component of
the encapsulated key and recipient (since the ML-KEM encapsulation key might not
be available without user presence, depending on how it is stored on the
hardware).

The body of the recipient stanza is the HPKE ciphertext from SealBase.

    -> p256mlkem768tag ...
    ...

The identity implementations MUST ignore any stanza that does not have
`p256mlkem768tag` as the first argument, and MUST otherwise reject any stanza
that has more or less than three arguments, or where the second argument is not
a canonical encoding of a 1153-byte value or the third argument is not a
canonical encoding of a 4-byte value. It MUST check that the body length is
exactly 32 bytes before attempting to decrypt it.

## ASCII armor

age files that need to be transmitted as 7-bit ASCII SHOULD be encoded according
to the strict PEM encoding specified in [RFC 7468][], Section 3 (Figure 3), with
case-sensitive label "AGE ENCRYPTED FILE". Note that this encoding employs
base64 with `=` padding characters, unlike the rest of this document.

Note that ASCII armored files are malleable unless care is taken to reject any
data before and after the PEM encoding, a strict PEM parser is used, and
canonical base64 is enforced. age implementations SHOULD reject non-canonical
ASCII armor encodings except for whitespace before and after the PEM block, and
MAY choose to accept both LF and CRLF line endings.

## Test vectors

A comprehensive set of test vectors is avaliable at
https://age-encryption.org/testkit.

[RFC 5234]: https://www.rfc-editor.org/rfc/rfc5234.html
[RFC 7405]: https://www.rfc-editor.org/rfc/rfc7405.html
[RFC 4648]: https://www.rfc-editor.org/rfc/rfc4648.html
[RFC 5869]: https://www.rfc-editor.org/rfc/rfc5869.html
[RFC 7539]: https://www.rfc-editor.org/rfc/rfc7539.html
[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html
[RFC 2104]: https://www.rfc-editor.org/rfc/rfc2104.html
[STREAM]: https://eprint.iacr.org/2015/189
[Tink]: https://github.com/google/tink/blob/59bb34495d1cb8f9d9dbc0f0a52c4f9e21491a14/docs/WIRE-FORMAT.md#streaming-encryption
[Miscreant]: https://github.com/miscreant/meta/wiki/STREAM
[Bech32]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
[RFC 7748]: https://www.rfc-editor.org/rfc/rfc7748.html
[RFC 7914]: https://www.rfc-editor.org/rfc/rfc7914.html
[RFC 7468]: https://www.rfc-editor.org/rfc/rfc7468.html
[RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180.html
[RFC 9180, Section 6.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-6.1
[SEC 1, Ver. 2]: https://www.secg.org/sec1-v2.pdf
[draft-ietf-hpke-pq-01]: https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-01
