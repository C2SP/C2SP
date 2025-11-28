# agead

agead is a seekable streaming encryption standard, built for use in the age file encryption standard.

It is a STREAM variant from [Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance][STREAM]. It is similar to those used by [Tink][] and [Miscreant][], but it doesn't prefix the AEAD nonce with key material as the payload key is 256 bits (enough even to provide a security margin in the multi-target setting) and derived from both the input key and the nonce.

## Conventions used in this document

Keys derived with HKDF-SHA-256 are produced by applying HKDF-Extract with the specified salt followed by HKDF-Expand with the specified info according to [RFC 5869][]. The hash used with HKDF in this specification is always SHA-256. The length of the output keying material is always 32 bytes.

ChaCha20-Poly1305 is the AEAD encryption function from [RFC 7539][].

`0x` followed by two hexadecimal characters denotes a byte value in the 0-255 range.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14][] [RFC 2119][] [RFC 8174][] when, and only when, they appear in all capitals, as shown here.

## Encrypting a payload

A user of streaming encryption wishes to encrypt a _payload_—a sequence bytes that is possibly long and whose full contents or length is possibly not known at the time encryption starts. 

The encryption algorithm is given a 32 byte key `k` and a 16-byte nonce `nonce`. The _payload key_ is computed as follows:

    payload key = HKDF-SHA-256(ikm = k, salt = nonce, info = "payload")

The payload is split in chunks of 64 KiB, and each of them is encrypted with ChaCha20-Poly1305, using the payload key and a 12-byte nonce composed as follows: the first 11 bytes are a big endian chunk counter starting at zero and incrementing by one for each subsequent chunk; the last byte is 0x01 for the final chunk and 0x00 for all preceding ones. The final chunk MAY be shorter than 64 KiB but MUST NOT be empty unless the whole payload is empty.

The payload can be streamed by decrypting or encrypting one chunk at a time. Streaming decryption MUST signal an error if the end of file is reached without successfully decrypting a final chunk.

The payload can be seeked by jumping ahead in chunk increments, and decrypting the whole chunk that contains the seeked position. Seeking relatively to the end of file MUST first decrypt and verify that the last chunk is a valid final chunk.

[RFC 5869]: https://www.rfc-editor.org/rfc/rfc5869.html
[RFC 7539]: https://www.rfc-editor.org/rfc/rfc7539.html
[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html
[STREAM]: https://eprint.iacr.org/2015/189
[Tink]: https://github.com/google/tink/blob/59bb34495d1cb8f9d9dbc0f0a52c4f9e21491a14/docs/WIRE-FORMAT.md#streaming-encryption
[Miscreant]: https://github.com/miscreant/meta/wiki/STREAM
