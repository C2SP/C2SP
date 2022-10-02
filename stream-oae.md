# STREAM construction for Online Authenticated Encryption

Version: 0.0.0
Maintainer: Jack Grigg

## Abstract

## STREAM

Parameters:

- AEAD: The underlying encryption system.
- AEAD.NonceLength
  - Should we restrict this to a specific length (range)?
- ChunkLength
  - Does this need to be a parameter?

Encryption:

- Split plaintext into pieces of length ChunkLength.
  - The last chunk MAY be short, but MUST NOT be empty.
    - TODO: Why are impls like this, and should they be?
- Encrypt each piece with AEAD, with a 


TODO:
- Figure out a nice abstraction that can handle the various instantiations.
  - Different AEADs have different nonce sizes.
- Maybe add an "implementation notes" section with tips for implementors?

## Nonce encodings

The STREAM construction is used by a number of in-production cryptographic protocols. We
specify their nonce encodings here for two reasons:

- To document the rationale for selecting a particular encoding.
- To encourage implementors to choose an existing encoding when considering STREAM for
  their protocols.

### STREAM-BE32

```
nonce_prefix || ctr || last_block
```

- `nonce_prefix`: 7-byte fixed prefix.
- `ctr`: 4-byte (32-bit) big-endian counter.
- `last_block`: 1-byte flag (`0x01` if this is the last block, `0x00` otherwise).

This instantiation is used by [Tink](https://developers.google.com/tink/streaming-aead).

> Rationale (from [this Miscreant issue](https://github.com/miscreant/meta/issues/32#issuecomment-343439065)):
>
> - `last_block` is a byte instead of a bit because the paper described it that way.
> 

### STREAM-BE88

```
ctr || last_block
```

- `ctr`: 11-byte (88-bit) big-endian counter.
- `last_block`: 1-byte flag (`0x01` if this is the last block, `0x00` otherwise).

This instantiation is used by [age](https://age-encryption.org/v1).

> Rationale: this encoding is similar to STREAM-BE32, but removes `nonce_prefix` as the
> higher-level protocol uses HKDF to derive its STREAM keys.
