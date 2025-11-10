# age piv-p256 recipient stanza

[c2sp.org/age-piv-p256](https://c2sp.org/age-piv-p256)

## Introduction

This document specifies the age piv-p256 recipient stanza. This stanza
is used for encryption using NIST P-256 keys stored on hardware tokens
or PIV devices.

Apart from using the NIST P-256 curve, the piv-p256 recipient stanza
differs from the native [X25519 recipient
stanza](https://age-encryption.org/v1#x25519-recipient-stanza) in that
it includes a tag of the recipient, to allow the recipient to select the
correct secret without the hardware token requesting user interaction.

**This is a historical specification, providing canonical documentation of
a recipient type in use by several age plugins. New implementations should 
consider implementing the [p256tag recipient type](https://age-encryption.org/v1#the-p256tag-recipient-type).** 


## Conventions used in this document

ABNF syntax follows [RFC
5234](https://www.rfc-editor.org/rfc/rfc5234.html) and [RFC
7405](https://www.rfc-editor.org/rfc/rfc7405.html) and references the
core rules in RFC 5234, Appendix B.1.

The base64 encoding used throughout is the standard Base 64 encoding
specified in [RFC 4648](https://www.rfc-editor.org/rfc/rfc4648.html),
Section 4, without `=` padding characters (sometimes referred to as
"raw" or "unpadded" base64). Encoders MUST generate canonical base64
according to RFC 4648, Section 3.5, and decoders MUST reject
non-canonical encodings and encodings ending with `=` padding
characters.

P256 is the scalar multiplication over P-256, with SEC 1 point decoding 
and encoding.

`||` denotes concatenation. `0x` followed by two hexadecimal characters
denotes a byte value in the 0-255 range.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT",
"SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and
"OPTIONAL" in this document are to be interpreted as described in [BCP
14](https://www.rfc-editor.org/info/bcp14) [RFC
2119](https://www.rfc-editor.org/rfc/rfc2119.html) [RFC
8174](https://www.rfc-editor.org/rfc/rfc8174.html) when, and only when,
they appear in all capitals, as shown here.

## Recipient stanza

A piv-p256 recipient stanza has three arguments.

    -> piv-p256 8u8pZg Aqa5k2Tm/BJGTzCno1W29dWaWBHkFchOztcIZ7aQo0Ca
    CXE0N0KMI0BUE5WaYTLOxYv7aHB/5IQpAZKsk2C/yjU

1.  The first argument is the fixed string `piv-p256`.

2.  The second argument is the base-64 encdoded tag of the recipient,
    consisting of the first 4 bytes of the SHA-256 hash of the
    recipient:

         tag = SHA-256(recipient)[0..4]

3.  The third argument is the base64-encoded ephemeral share computed by
    the recipient implementation as follows:

         ephemeral secret = read(CSPRNG, 32)
         ephemeral share = P256(ephemeral secret, basepoint)

    A new ephemeral secret MUST be generated for each stanza and each
    file.

The body of the recipient stanza is computed by the recipient
implementation as

    salt = ephemeral share || recipient
    info = "piv-p256"
    shared secret = P256(ephemeral secret, recipient)
    wrap key = HKDF-SHA-256(ikm = shared secret, salt, info)
    body = ChaCha20-Poly1305(key = wrap key, plaintext = file key)

where the ChaCha20-Poly1305 nonce is fixed as 12 0x00 bytes.

The identity implementation MUST ignore any stanza that does not have
`piv-p256` as the first argument, and MUST otherwise reject any stanza
that has more or less than three arguments, or where the second argument
is not a canonical encoding of a 4-byte value, or the third argument is
not a canonical encoding of a 32-byte value. It MUST check that the body
length is exactly 32 bytes before attempting to decrypt it.

The identity implementation MUST ignore any stanza with a tag for which
it does not have any corresponding secret.

The identity implementation computes the shared secret as follows:

    shared secret = P256(identity, ephemeral share)

If the shared secret is the point at infinity, the identity implementation
MUST abort.

Finally, it derives the key as above and decrypts the file key in the
body.

## Changelog

- **v0.0.1**: Initial draft
