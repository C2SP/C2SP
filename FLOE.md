# Fast Lightweight Online Encryption (FLOE)

[c2sp.org/FLOE](https://c2sp.org/FLOE)

## Introduction

Fast Lightweight Online Encryption (FLOE) is a cryptographic construction designed by [Snowflake](https://www.snowflake.com/) for the encryption of large files.

If any security issues are found with FLOE or the implementations, please contact us at [security@snowflake.com](mailto:security@snowflake.com).

The official Snowflake-owned copy of the specification is available at [github.com/Snowflake-Labs/floe-specification](https://github.com/Snowflake-Labs/floe-specification). That repository also contains reference implementations, links to third-party implementations, and test vectors.

## Motivation

Snowflake, like many other companies, needs to works with very large files containing sensitive data.
Encryption is one of many tools that we use to protect this data and fulfill our promises to our customers.
Unfortunately, we determined that there are no good existing cryptographic constructions for the symmetric encryption of multi-gigabyte files.

All existing constructions fail one or more of our three primary requirements:

- Authenticated encryption  
  Essentially, this means that an attacker must not be able to cause incorrect data to be decrypted.
- Bounded memory  
  Regardless of the data size, an implementation must be able to successfully encrypt/decrypt it using a constant amount of memory.
- FIPS Compatible  
  The construction must be able to be implemented using nothing more than FIPS validated cryptographic modules in fully compliant ways.

The first of these requirements is a basic requirement of any modern cryptographic construction.
However, the need to validate the data upon decryption causes most constructions (such as AES-GCM) to need to hold the entire plaintext in memory before releasing it to the caller.
In the case of a 2 gigabyte file, this means you are spending 2 gigabytes of memory just to hold data which you might normally be able to handle in a streaming manner.
(For example, if you are downloading and decrypting a file from the network as part of writing it to local storage, you should not need to hold the whole file in memory at once. Instead, you should be able to stream it while only maintaining a small buffer of active data.)
The "streaming" property described above is what is known technically as "online encryption."

Once we determined that there we no existing solutions, we came up with a list of additional requirements for FLOE.
While none of these requirements would have prevented us from adopting an existing solution,
if we need to build something new anyway, we want the result to be better in as many ways as possible.

- Useful error messages  
  Many cryptographic constructions only tell callers that something has failed and cannot give greater insight into what went wrong.
  This can make encrypted systems very challenging to debug.
  FLOE gives (safe) useful error messages when decrypting which help with debugging.
- Commitment  
  Some cryptographic constructions allow attackers (who know the keys) to craft a single ciphertext which can be decrypted by multiple keys.
  In certain limited protocols this can lead to other protocol-specific problems.
  Because FLOE is committing, an attacker cannot do this.
- Random access reads  
  We don't always want to decrypt an entire file in order from the beginning to the end.
  Sometimes we want to read and decrypt arbitrary subsections of it.
  FLOE must allow us to decrypt arbitrary subsections (subject to some reasonable overhead) while still giving us the same security properties for all read data we'd get for the entire file.
- Easy to implement safely  
  Implementation flaws in cryptographic code are often more significant than algorithmic flaws.
  FLOE is designed to be easy to safely implement given nothing more than SHA-256 and AES-GCM.
- Misuse resistant  
  Many otherwise secure cryptographic algorithms break when misused.
  For symmetric encryption, this is primarily through IV reuse, key wearout, or key misuse.
  FLOE is designed to defend against all three of these issues.
  FLOE does not take in an external IV.
  Internal KDFs mean that a single key can be used to encrypt messages before cryptographic wearout occurs.
  (Reasonable parameters permit up to 2<sup>65</sup> bytes or 32 exabytes, with an adversarial advantage of &lt;2<sup>-32</sup>.)
  The internal KDF also makes it highly unlikely that even if a key were to be used with FLOE and another cryptographic algorithm that the security of data *encrypted with FLOE* would remain intact.
- Externally reviewed  
  Any cryptographic proposal must be carefully reviewed by numerous experts.
  In addition to our in house cryptographers, we also consulted with experts from Cornell and UNC.
  The resulting paper "Random-Access AEAD for Fast Lightweight Online Encryption" is available on the [IACR ePrint servers](https://eprint.iacr.org/2025/2275) and has been accepted both Real World Crypto 2026 and Eurocrypt 2026.

  As of now, no security issues have been found with the design.

## Specification

Fast Lightweight Online Encryption (FLOE) is a secure random access authenticated encryption (raAE) scheme as defined in [Random-Access AEAD for Fast Lightweight Online Encryption](https://eprint.iacr.org/2025/2275).
All secure (ra-ROR) raAE schemes are also nOAE2 secure as defined by [HRRV15](https://eprint.iacr.org/2015/189).
FLOE is inspired heavily by the work in HRRV15 and others.
FLOE can be thought of as a family of algorithms, each specified by a set a parameters.
(This is similar to how [HPKE](https://www.rfc-editor.org/rfc/rfc9180.html) is defined.)

This specification defines four *public* functions for the random access case (raAE): `startEncryption`, `encryptSegment` and their decryption equivalents.
For usecases that do not require random access, we strongly recommend that instead of exposing `encryptSegment` and `decryptSegment` that you expose the sequention/online equivalents of them:
`encryptOnlineSegment`, `encryptLastSegment`, and their decryption equivalents.
These four methods (along with the two `start` functions) support the online/sequential use case and are harder to misuse.
An implementation may choose not to expose those methods directly to callers but instead implement its own API on top of the "official" FLOE functions.

### Terminology

Both FLOE and its internal AEAD use data of similar types (keys, IVs, AADs, etc.).
In all cases we explicitly specify which we're referring to.

All lengths are in bytes unless otherwise specified.

### Parameters

FLOE is parameterized by four values:

- `AEAD`  
  Used to actually encrypt the data
- `KDF`  
  Used to derive keys for the AEAD and other values
- `FLOE_IV_LEN`
  The length, in bytes, of the FLOE IV  
- `ENC_SEG_LEN`  
  The length of a single segment of a FLOE ciphertext.
  It is necessarily longer than the associated plaintext data for a segment.

These parameters then define a large number of derived parameters.

Currently, only `ENC_SEG_LEN` can take different values.
The other three parameters are *fixed* as follows:

- **AEAD:** AES-GCM-256
- **KDF:** HKDF-EXPAND-SHA-384
- **FLOE_IV_LEN:** 32

#### Derived Parameters

These parameters are all defined implicitly by selection of one of the main parameters listed above.

|  `AEAD` | `AEAD_ID` | `AEAD_KEY_LEN` | `AEAD_IV_LEN` | `AEAD_TAG_LEN` | `AEAD_ROTATION_MASK` | `AEAD_MAX_SEGMENTS` |
| :---- | :---- | :---- | :---- | :---- | :---- | :---- |
| AES-GCM-256 | 0 | 32 | 12 | 16 | 20 | 2<sup>40</sup> |

- `AEAD_ID`  
  An integer representing the selected AEAD
- `AEAD_KEY_LEN`  
  The length, in bytes, of the key expected by the AEAD
- `AEAD_IV_LEN`  
  The length, in bytes, of the IV expected by the AEAD
- `AEAD_TAG_LEN`  
  The length, in bytes, of the tag returned by the AEAD
- `AEAD_ROTATION_MASK`
  A non-negative integer value designating how many segments can be encrypted before deriving a new encryption key.
  Specifically, 2<sup>`AEAD_ROTATION_MASK`</sup> segments are encrypted under a single key.
- `AEAD_MAX_SEGMENTS`  
  The maximum number of segments in a FLOE ciphertext which uses the selected AEAD.
  Implementations may place lower limits on what they are willing to produce or accept.

| `KDF` | `KDF_ID` | `KDF_KEY_LEN` |
| :---- | :---- | :---- |
| HKDF-EXPAND-SHA-384 | 0 | 48 |

- `KDF_ID`  
  An integer representing the selected KDF
- `KDF_KEY_LEN`  
  An integer representing the length, in bytes, of the key to derive for use as a KDF key

### FLOE Ciphertext Layout

A FLOE ciphertext consists of two parts: `FLOE_HEADER` and `FLOE_BODY`

The `FLOE_HEADER` consists of three parts:

1. Parameter Information: 10 bytes  
   `PARAM_ENCODE(params)`  
2. IV: `FLOE_IV_LEN` bytes  
3. Header tag: `32` bytes  
   Output of `FLOE_KDF(key, iv, aad, "HEADER_TAG:", 32)`

The `FLOE_BODY` consists of zero or more internal segments and a single final segment.
Each internal segment is exactly `ENC_SEG_LEN` bytes long.
The final segment may be between `AEAD_IV_LEN + AEAD_TAG_LEN + 4` and `ENC_SEG_LEN` (inclusive) bytes long.

A segment consists of four pieces:

1. A final length value encoded with `I2BE(*, 4)`  
   This value is max (`0xFFFFFFFF`) for all non-final segments and is the *total encrypted segment length* of the last segment.
   This means that it includes the lengths of the: length value, AEAD IV, AEAD ciphertext, and AEAD tag
2. A random IV of `AEAD_IV_LEN` bytes  
3. A ciphertext encrypted with the AEAD.
  (The length is implicit and can be derived from context.)  
4. The tag of `AEAD_TAG_LEN` bytes

### Key Generation

FLOE keys MUST be of equal length to `AEAD_KEY_LEN`.
They MUST meet the standard security requirements for symmetric keys of that length. ([NIST SP 800-133](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-133r2.pdf), Section 6\)

### Implementation

#### External Functions

These are functions that are not specific to FLOE and are likely provided by external or standard libraries.
While their behavior is defined, their implementation is out of scope for this specification.

- `I2BE(val, len) -> bytes`  
  Encodes `val` as an unsigned big-endian value of exactly `len` bytes.
  It will never be called with a value out of range.
- `RND(len) -> bytes`  
  Returns `len` cryptographically random bytes.
- `AEAD_ENC(key, data, aad) -> (iv, ct, tag)`  
  The encryption function as defined by the AEAD.
  Internal IV generation is as defined by the algorithm, and thus generally equivalent to `iv = RND(AEAD_IV_LEN)`.
- `AEAD_DEC(key, iv, ct, aad, tag) -> pt`  
  The decryption function as defined by the AEAD.
  On failure **throws** an appropriate exception.
- `KDF(prk, info, len) -> bytes`  
  The KDF as defined by `KDF`.
- `len(a) -> int`  
  Returns the length of byte-string `a`.
- `a || b -> bytes`  
  Concatenation. Returns the concatenation of byte strings `a` and `b`.
- `assert(val)`  
  If `val` is false, then **throws** an appropriate exception. This exception is permitted to be meaningful and indicate where and how the failed assertion occurred.
- `ctEq(val1, val2)`  
  Checks `val1` and `val2` for equality *in constant time*. Returns `true` or `false` as appropriate.
- `throw(msg)`  
  Throws an exception with the specified message.

#### Internal Functions

These are FLOE-specific functions that may need to be implemented.
None of these are exposed to callers.
Depending on how you implement the code, these may be inlined, provided by the programming language, or otherwise refactored.

- `SPLIT(data, prefix_len, suffix_len) -> (prefix, body, suffix)`  
    Takes the byte string `data` and splits it into three parts `prefix`, `body`, and `suffix` such that:  
  - `prefix` is exactly `prefix_len` bytes long  
  - `suffix` is exactly `suffix_len` bytes long  
  - `prefix || body || suffix = data`  
  - It aborts if the above is not possible
- `PARAM_ENCODE(params) -> bytes`  
  Defined as `I2BE(AEAD_ID, 1) || I2BE(HASH_ID, 1) || I2BE(ENC_SEG_LEN, 4) || I2BE(FLOE_IV_LEN, 4)`.
  The output is always exactly 10 bytes long.
- `FLOE_KDF(key, iv, aad, purpose, len) -> byte[len]`  
  Defined as `KDF(key, PARAM_ENCODE(params) || iv || purpose || aad, len)` where `params` is implicit from the context.
- `MASK(val, bits) -> int`  
  Returns `val` with bits of its low-order bits masked to `0` values.
- `DERIVE_KEY(key, iv, aad, segmentNumber) -> key`  
  Defined as `FLOE_KDF(key, iv, aad, "DEK:" || I2BE(MASK(segmentNumber, AEAD_ROTATION_MASK), 8), AEAD_KEY_LEN)`.
  This value may be internally cached by implementations.

#### Semi-Public Functions (Random Access)

FLOE can be defined in terms of four functions which support random access (as per the raAE definition).
While this interface is a fully secure one (as per raAE) it does not protect developers against their own mistakes
as much as the streaming/online interface.
Thus, these methods should generally be internal implementation details.
However, depending on the specific use-case, these APIs may be the correct level of abstraction to be made public.
They are more challenging to use correctly because they no longer protect the developer from a number of mistakes:

- They do not enforce that all required segments are encrypted.  
- They do not enforce that `encryptSegment` is never called multiple times for a given position/terminal indicator
- They do not prevent encryption of segments with higher positions than the terminal segment
- If a decryptor does not already know the correct length of the ciphertext (i.e., maximum position) then it is difficult for them to distiguish truncation versus just trying to read past the end.
- If an adversary can cause a decryptor to attempt decryption of a valid segment with the incorrect position/terminal indicator, then FLOE loses commitment properties.

In practice, this means that these API should likely not be exposed directly to developers but instead be used to construct higher-level (safe) APIs.
For example, a developer of a client-side encryption library for cloud block storage, might choose to use FLOE.
While they could simply use the online APIs above to stream the file to the cloud, using these random access APIs would permit them to spin up a number of threads to encrypt (and possibly upload) segments in parallel.
Similarly, they could use these random access APIs to do random reads of the uploaded object.

```txt
startEncryption(key, aad) -> (State, Header)
  iv = RND(FLOE_IV_LEN)

  HeaderPrefix = PARAM_ENCODE(params) || iv
  HeaderTag = FLOE_KDF(key, iv, aad, "HEADER_TAG:", 32)
  MessageKey = FLOE_KDF(key, iv, aad, "MESSAGE_KEY:", KDF_KEY_LEN)
  Header = HeaderPrefix || HeaderTag

  State = {MessageKey, iv, aad}
  return (State, Header)
```

```txt
startDecryption(key, aad, header) -> State
  EncodedParams = PARAM_ENCODE(params)
  assert(len(header) == FLOE_IV_LEN + len(EncodedParams) + 32)

  (HeaderParams, iv, HeaderTag) = SPLIT(header, len(EncodedParams), 32)
  assert(HeaderParams == EncodedParams)

  ExpectedHeaderTag = FLOE_KDF(key, iv, aad, "HEADER_TAG:")
  if ctEq(ExpectedHeaderTag, HeaderTag) == FALSE: // Must be constant time
    throw("Invalid Header Tag")

  MessageKey = FLOE_KDF(key, iv, aad, "MESSAGE_KEY:", KDF_KEY_LEN)
  State = {MessageKey, iv, aad}
  return State
```

```txt
encryptSegment(State, plaintext, position, is_final) -> (State, EncryptedSegment)
  assert(len(plaintext) >= 0)
  if is_final:
    assert(len(plaintext) <= ENC_SEG_LEN - AEAD_IV_LEN - AEAD_TAG_LEN - 4)
    aad_tail = 0x01
  else:
    assert(len(plaintext) == ENC_SEG_LEN - AEAD_IV_LEN - AEAD_TAG_LEN - 4)
    aad_tail = 0x00

  aead_key = DERIVE_KEY(state.MessageKey, state.iv, state.aad, position) 
  aead_iv = RND(AEAD_IV_LEN)
  aead_aad = I2BE(position, 8) || aad_tail
  (aead_ciphertext, tag) = AEAD_ENC(aead_key, aead_iv, plaintext, aead_aad)

  if is_final:
    FinalSegementLength = 4 + AEAD_IV_LEN + len(aead_ciphertext) + AEAD_TAG_LEN
    segment_header = I2BE(FinalSegementLength, 4) || aead_iv || aead_ciphertext || tag
  else:
    segment_header = 0xFFFFFFFF

  EncryptedSegment = segment_header || aead_iv || aead_ciphertext || tag
  return (State, EncryptedSegment)
```

```txt
decryptSegment(State, EncryptedSegment, position, is_final) -> (State, Plaintext)
  if is_final:
    assert(len(EncryptedSegment) >= AEAD_IV_LEN + AEAD_TAG_LEN + 4)
    assert(len(EncryptedSegment) <= ENC_SEG_LEN)
    assert(BE2I(EncryptedSegment[:4]) == len(EncryptedSegment))
    aad_tail = 0x01
  else:
    assert(len(EncryptedSegment) == ENC_SEG_LEN)
    assert(BE2I(EncryptedSegment[:4]) == 0xFFFFFFFF)
    aad_tail = 0x00

  aead_key = DERIVE_KEY(state.MessageKey, state.iv, state.aad, position)
  (aead_iv, aead_ciphertext, tag) = SPLIT(EncryptedSegment[4:], AEAD_IV_LEN, AEAD_TAG_LEN)
  aead_aad = I2BE(position, 8) || aad_tail

  // Next line will throw if AEAD decryption fails
  Plaintext = AEAD_DEC(aead_key, aead_iv, aead_ciphertext, aead_aad)

  return (State, Plaintext)
```

#### Public Streaming/Online Function

These functions provide a safe interface to FLOE and are the recommended public API.

```txt
startOnlineEncryption(key, aad) -> (State, Header)
  (State, Header) = startEncryption(key, aad)
  State.Counter = 0
  State.Closed = False
  return (State, Header)
```

```txt
encryptOnlineSegment(State, plaintext) -> (State, EncryptedSegment)
  assert(State.Closed == False)
  assert(State.Counter != AEAD_MAX_SEGMENTS - 1)

  (State, EncryptedSegment) = encryptSegment(State, plaintext, State.Counter, False)

  State.Counter++
  return (State, EncryptedSegment)
```

```txt
encryptLastSegment(State, plaintext) -> EncryptedSegment
  assert(State.Closed == False)
  
  (State, EncryptedSegment) = encryptSegment(State, plaintext, State.Counter, True)

  State.Closed = True
  return EncryptedSegment
```

```txt
startOnlineDecryption(key, aad, header) -> State
  State = startDecryption(key, aad, header)
  State.Counter = 0
  State.Closed = False
  return State
```

```txt
decryptOnlineSegment(State, EncryptedSegment) -> (State, Plaintext)
  assert(State.Closed == False)
  assert(State.Counter != AEAD_MAX_SEGMENTS - 1)

  (State, Plaintext) = decryptSegment(State, EncryptedSegment, State.Counter, False)

  State.Counter++
  return (State, Plaintext)
```

```txt
decryptLastSegment(State, EncryptedSegment) -> Plaintext
  assert(State.Closed == False)

  (State, Plaintext) = decryptSegment(State, EncryptedSegment, State.Counter, True)

  State.Closed = True
  return Plaintext
```

##### Auxiliary Public Online Decryption Function

This is a helper function which makes the FLOE API nicer to use but has no impact on its correctness or security properties.

```txt
decryptAnyOnlineSegment(State, EncryptedSegment) -> (State, Plaintext)
  if BE2I(EncryptedSegment[:4]) == 0xFFFFFFFF:
    return decryptSegment(State, EncryptedSegment)
  else:
    return decryptLastSegment(State, EncryptedSegment)
```
