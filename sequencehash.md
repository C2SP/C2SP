# SequenceHash and SequenceMAC

[c2sp.org/sequencehash](https://c2sp.org/sequencehash)

- **Version**: v0.1.0
- **Authors**: Opal Wright and Scott Arciszewski

SequenceHash is a TupleHash-like construction for unambiguously hashing sequences of bytestrings.

## Introduction

Computing a hash or MAC from multiple bytestrings is difficult. Cryptographic hash functions are designed around processing a single, contiguous bytestring (or bitstring), and simply concatenating multiple values into a single input can lead to ambiguous encodings and accidental "collisions".

SequenceHash is designed to solve this issue, making it easy to _safely_ compute hashes of sequences of bytestrings. It uses a double-hash construction (similar to HMAC) and a fast, unambiguous encoding mechanism in order to provide TupleHash functionality for hash functions beyond Keccak.

## Features

### Hash-agnostic

SequenceHash is structurally similar to HMAC, and, like HMAC, can be used with most underlying hash functions, such as SHA-256, BLAKE2, RIPEMD, etc. SequenceHash outputs are not subject to length-extension attacks, even when an underlying hash function is.

### Byte-orientation

SequenceHash operates natively on _bytes_, not _bits_. Most hashing these days is done in software, operating on strings of bytes. SequenceHash is built around this assumption, which simplifies both specification and implementation.

### Customization strings

SequenceHash includes native support for customization strings to allow for user-level domain separation of hashes. This can be useful in several contexts, such as preventing replay of earlier messages in multi-round protocols, or locking Fiat-Shamir transcripts to a specific proof type.

Customization strings are optional: if not specified by a user, the empty string is used.

### Keyed mode

SequenceHash has a sister function, SequenceMAC. SequenceMAC accepts keys that are at least 32 bytes long, and supports customization strings as well.

## Notation and terms

We denote exponentiation with `^`, and concatenation of bytestrings with `||`. All bytestrings are given in hexadecimal; integer values are given in decimal.

In some of the examples, we will place notes or comments next to inputs and pseudocode. These will be marked with the comment indicator `#`, which continues to the end of the line.

We use the terms MUST and MUST NOT to indicate that an implementation cannot be considered compliant with the specification if the condition described is not met.

We use the terms SHOULD and SHOULD NOT to describe behaviors that are considered best practice. An implementation that deviates from SHOULD/SHOULD NOT guidance can still be compliant, but implementers are strongly encouraged to clearly document such deviations from SHOULD/SHOULD NOT guidance. For instance, implementations SHOULD zeroize key material when no longer needed (though the determination of how long key material may be needed is left to implementers).

We use the term MAY to indicate optional behavior that is not required for compliance with the specification, but that implementers can include at their own discretion without compromising specification compliance. For example, implementations MAY emit warnings or raise errors when known-weak hash functions are used. Implementers are encouraged to document such decisions.

In general, we will refer to a hash function using the letter `H`, the block size of `H` as `b`, and the output length of `H` as `L`.

The term "short hash" refers to a hash function `H` where `L < 32`.

## Support functions and general requirements

### Hash function support

As a general matter, the security guarantees for SequenceHash and SequenceMAC do not apply if the underlying hash functions are not secure. A hash function may be considered insecure due to cryptanalytic results (such as MD4, MD5, and SHA-0). A hash function may also be considered insecure due to the length of the output (MD4, MD5, SHA-1, RIPEMD128).

Implementations MAY reject hash functions with known security issues or short outputs. Implementations that do so MUST document excluded hash functions (either by hash function name or by criteria used for rejection).

Implementations SHOULD emit warnings when using SequenceMAC with hashes whose output is less than 32 bytes.

### Input lengths

The SequenceHash and SequenceMAC _specification_ supports up to (2^128) - 1 inputs of (2^128) - 1 bytes each (plus a length encoding), which would require the underlying hash to process nearly 2^256 bytes of input. This exceeds the maximum input length of many hash functions, leading to potential confusion.

Implementations MAY track aggregated input lengths to ensure that input length limits of underlying hash functions are not exceeded. Implementations that do so MUST refuse to accept data that would exceed the limits of the underlying hash function.

Implementations MUST limit individual inputs to 2^128 - 1 bytes in length. In practice, we don't expect this to present a problem; most APIs will likely limit individual input lengths to those representable by 32-bit or 64-bit integers.

We provide a table below of maximum input lengths (in bytes) for several common hash functions. Note that the SHA3 standard does not impose an input length limit.

| Hash function     | Maximum total input (bytes)   |
|---                |---                            |
| SHA-256           | 2^61 - 1                      |
| SHA-384           | 2^125 - 1                     |
| SHA-512           | 2^125 - 1                     |
| BLAKE2b           | 2^128 - 1                     |
| BLAKE2s           | 2^64 - 1                      |
| WHIRLPOOL         | 2^253 - 1                     |
| RIPEMD160         | 2^61 - 1                      |
| SHA3-256          | (no maximum)                  |
| SHA3-384          | (no maximum)                  |
| SHA3-512          | (no maximum)                  |


### `EncodeMSBF`

`EncodeMSBF` stands for "Encode Most Significant Byte First". It converts a 128-bit unsigned integer `R` into a 16-byte representation `r = [r_0, r_1, ..., r_15]` such that `sum([r[15 - i] * 2 ^ (8 * i) for i in 0 ... 15]) == R`. So `r_0` is the most-significant byte of the representation of `R`.

Negative values or values too large to be represented as an unsigned 128-bit integer MUST be rejected.

Examples:

```
EncodeMSBF(0)                                       = 00000000000000000000000000000000

EncodeMSBF(1)                                       = 00000000000000000000000000000001

EncodeMSBF(170141183460469231731687303715884105728) = 80000000000000000000000000000000

EncodeMSBF(82056233853955569762636142348112307994)  = 3dbb74aeac45747d1c1a44915219271a

EncodeMSBF(-1)                                      => ERROR

EncodeMSBF(340282366920938463463374607431768211456) => ERROR
```

Implementations MAY impose upper bounds smaller than (2^128) - 1. For instance, an implementation targeting a 32-bit processor may limit inputs to the range [0, (2^32) - 1], and use zero padding on the left to obtain a 16-byte value. Implementations MUST NOT impose a different lower bound.

### `EncodeLSBF`

`EncodeLSBF` stands for "Encode Least Significant Byte First". It converts a 128-bit unsigned integer `R` into a 16-byte representation `r = [r_0, r_1, ..., r_15]` such that `sum([r[i] * 2 ^ (8 * i) for i in 0 ... 15]) == R`. So `r_0` is the least-significant byte of the representation of `R`.

Negative values or values too large to be represented as an unsigned 128-bit integer MUST be rejected.

Examples:

```
EncodeLSBF(0)                                       = 00000000000000000000000000000000

EncodeLSBF(1)                                       = 01000000000000000000000000000000

EncodeLSBF(170141183460469231731687303715884105728) = 00000000000000000000000000000080

EncodeLSBF(82056233853955569762636142348112307994)  = 1a27195291441a1c7d7445acae74bb3d

EncodeLSBF(-1)                                      => ERROR

EncodeLSBF(340282366920938463463374607431768211456) => ERROR
```

Implementations MAY impose upper bounds smaller than (2^128) - 1. For instance, an implementation targeting a 32-bit processor may limit inputs to the range [0, (2^32) - 1], and use zero padding on the right to obtain a 16-byte value. Implementations MUST NOT impose a different lower bound.

### `Pad`

`Pad` is used to pad a bytestring with zeroes on the right to the smallest _positive_ multiple of size of a positive integer `b` (in practice, `b` will be the underlying block size of a hash function `H`). A non-empty bytestring that is already a multiple of the block length requires no padding. Given a hash function `H` with a block size `b` and a bytestring `S`, `Pad(S, b) = S` if `len(S) % b == 0` and `len(S) > 0`; otherwise, `Pad(S, b) = S || 00 || ... || 00`, where the number of zero bytes is equal to `b - (len(S) % b)`. Note that the empty string is padded to a full block of zeroes: `Pad('', b) = 00 * b`.

The output of `Pad` MUST always be non-empty and have length equal to a positive integer multiple of `b`. The first `len(x)` bytes of the output of `Pad(x, b)` will always equal `x`.

In pseudocode:

```
Pad(x, b):
    if len(x) == 0:
        return 00 || ... || 00 # Zero byte repeated b times
    if len(x) % b == 0:
        return x
    return x || 00 || ... || 00 # Zero byte repeated (b - len(x) % b) times
```

Examples, given `b = 64` (which is the block size of SHA-256):

```
Pad('', 64) = 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

Pad('JJJ', 64) = 4a4a4a00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

Pad('WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW', 64) = 57575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757

Pad('WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW', 64) = 5757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

### `Encode`

The `Encode` function provides an unambiguous encoding of a bytestring of length shorter than 2^128 bytes. It works by prepending a 128-bit (16-byte) length indicator, encoded with `EncodeLSBF`, to the bytestring. That is, `Encode(x) = EncodeLSBF(len(x)) || x`.

Note that empty bytestrings are NOT ignored. They are encoded as having length zero.

Examples:
```
Encode('')  = 00000000000000000000000000000000

Encode('AAA')  = 03000000000000000000000000000000414141

Encode('SEQUENCEHASH')  = 0c00000000000000000000000000000053455155454e434548415348
```

Implementations MUST NOT accept bytestrings longer than (2^128) - 1 bytes.

Implementations MAY limit bytestrings to lengths below (2^128) - 1. This can include limiting bytestring length based on the underlying hash function, or limiting bytestring length for performance or system compatibility issues.


### `Derive`

The `Derive` function processes keys and customization strings into key and customizer blocks, following the HMAC model. Inputs that are no longer than the block length of the underlying hash function are padded to the block size of the hash. Inputs that are longer than the block size of the underlying hash are hashed, then padded to the block size of the hash.

In pseudocode, given hash function `H` with block length `b` and an input bytestring `I`:

```
Derive(I, H, b):
    if len(I) <= b:
        I' = Pad(I, b)
    else:
        I' = Pad(H(I), b)
    return I'
```

Examples, given SHA-256 as `H`, which has `b = 64`:

```
Derive('', SHA-256, 64) = 00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

Derive('WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW', SHA-256, 64) = 57575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757575757

Derive('WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW', SHA-256, 64) = a86baffba4cd6018bebed0b8ed10bbe3ea892a8dfb03b992d2e270b3eb9faa8a0000000000000000000000000000000000000000000000000000000000000000
```

Note that `b` MUST match the block size of `H`.

## Function indicators

To prevent collisions between the two functions, SequenceHash and SequenceMAC incorporate distinct function indicators. These values are encoded as 128-bit integers using the `EncodeMSBF` function. As the SequenceHash and SequenceMAC family of functions grows (say, a future version adds XOF support), more function indicators will be added. All values aside from those given below are reserved for future use.

Currently, the only defined function indicators are `F_SEQHSH = 2` (for SequenceHash) and `F_SEQMAC = 1` (for SequenceMAC). Function indicators other than `F_SEQHSH` and `F_SEQMAC` MUST NOT be used.

## Header blocks

As mentioned previously, SequenceHash and SequenceMAC rely on an HMAC-like construction. To ensure that the inner and outer hashes are derived independently, each has a distinct "run-up" before processing the derived key block (which will be all-zero in the case of SequenceHash). This ensures that the key blocks are processed from different starting states, leading to independently-keyed inner and outer hash functions. Our header functions are as follows:

```
HeaderI(b, F, K):
    return Pad( 'SEQHSH_I'      ||
                EncodeMSBF(F)   ||
                EncodeMSBF(len(K)), b)
```

and

```
HeaderO(b, F, S, K):
    return Pad( 'SEQHSH_O'          ||
                EncodeMSBF(F)       ||
                EncodeMSBF(len(S))  ||
                EncodeMSBF(len(K)), b)
```

Even when `S` and `K` are both empty strings, we can see that the output of `HeaderI` will never match the output of `HeaderO`, as the leading 8 bytes will be distinct.

## SequenceHash and SequenceMAC specification

### SequenceFunction

Both SequenceHash and SequenceMAC are specific instances of a more general function we will call SequenceFunction. SequenceFunction is instantiated with four main parameters: a hash function `H` with block size `b`, a key `K` (possibly empty), a customization string `S` (possibly empty), and a function indicator `F`.

```
SequenceFunction(H, K, S, F; M_1, M_2, ..., M_n) =
    H(
        HeaderO(b, F, S, K)             ||
        S'                              ||
        K'                              ||
        EncodeMSBF(n)                   ||
        EncodeMSBF(L)                   ||
        H(
            HeaderI(b, F, K)            ||
            K'                          ||
            Encode(M_1)                 ||
            ...                         ||
            Encode(M_n)
        )
    )
```

Please note that, while the notation `M_1` through `M_n` suggests at least one input is required, this is not true. SequenceFunction, and the specific instantiations of SequenceHash and SequenceMAC (described below), can be computed over an empty set of inputs.

### SequenceMAC

We define SequenceMAC in terms of SequenceFunction:

```
SequenceMAC(H, K, S; M_1, ..., M_n) = SequenceFunction(H, K, S, F_SEQMAC; M_1, ..., M_n) IFF len(K) >= 32
```

Implementations MUST reject `K` if `len(K) < 32`; initialization of SequenceMAC MUST fail.

Implementations SHOULD emit warnings if a short hash is used.

Implementations MAY prohibit short hashes.

Implementations SHOULD zeroize `K` and `K'` when no longer needed for computations.

#### SequenceMAC keys and hash function selection

As noted in the definition, SequenceMAC keys are _required_ to be at least 32 bytes long.

When hash functions with `L > 32` are used, we recommend that keys satisfy `len(K) == L`. Implementations MAY emit warnings when `len(K) != L`.

For short hashes, the MAC security is bounded by `L`, regardless of key length. Implementations that allow short hashes SHOULD document the risks of using short hashes.

Implementations SHOULD emit warnings for short hashes, even when `len(K) >= 32`.

Implementations MAY prohibit short hashes. Implementations that allow short hashes MAY emit warnings to indicate when short hashes are used.


### SequenceHash

As with SequenceMAC, we define SequenceHash in terms of SequenceFunction:

```
SequenceHash(H, S; M_1, ..., M_n) = SequenceFunction(H, '', S, F_SEQHSH; M_1, ..., M_n)
```

From a glance, we can see that SequenceHash is nearly identical to SequenceMAC, differing only in the use of an empty key and a different function indicator.

As with SequenceMAC, implementations MAY prohibit short hashes. Implementations MAY emit warnings when short hashes are used. Implementations that allow short hashes SHOULD document the risks of using short hashes.

## Implementation Guidance

### APIs

Because SequenceHash and SequenceMAC behave differently from standard hash and MAC functions, it is important for implementers to help users navigate these differences.

#### Standard streaming APIs

Many popular hash APIs-- for instance, OpenSSL's `EVP_DIGEST`, Python's PEP 452, the Rust `Digest` trait-- support a "streaming" interface, under which a "write" or "update" call will process new input by (in effect) concatenating to previous inputs.

Matching streaming APIs can introduce compatibility problems when users rely on concatenation behavior. This does not bar SequenceHash/SequenceMAC implementers from supporting streaming APIs. It does mean that implementers should consider expected usage patterns and provide clear documentation.

#### One-shot APIs

Another popular API for hash functions is the "one-shot" API, in which the hash of a bytestring is computed as a single step-- e.g., `message_digest = SHA-256(input)`. This is the interface provided by the WebCrypto API's `Crypto.subtle.digest` method, for instance.

Since SequenceHash and SequenceMAC operate on _sequences_ of bytestrings, one-shot APIs may need to be extended to include support for multiple bytestrings. This can present a challenge from an API standpoint. Some programming languages support variadic functions, while others might make it necessary to pass the inputs as part of an array or vector.

#### Special considerations for large inputs

It is not always possible to know the size of an input in advance, such as when hashing streamed data. Because SequenceHash relies on a length-_prefix_ encoding, this can be a problem, especially in low-memory systems where caching the data isn't always possible.

In these cases, we recommend addressing the issue at the protocol level. For instance, users can apply their selected hash function to the incoming data while tracking its length, then update the SequenceHash or SequenceMAC instance twice: once with the length of the data (encoded using `EncodeLSBF`), then with the hash of the data.

#### Multiple customization strings

The inner hash of a SequenceHash computation does not incorporate the customization string. This means that, when the same values are being hashed under multiple customization strings, the inner hash value can be reused each time, avoiding costly re-hashing of inputs.

This also applies to SequenceMAC when the same key is used with different customization strings.

### Block size guidance

The concept of "block size" is well-understood for most Merkle-Damgard hash functions. However, sponge constructions have become more common in recent years, and the terminology is more complicated. For instance, the SHA3 standard specifies both a "rate" and a "capacity". In this case, the block size is the _rate_, not the capacity.

We provide a table of block sizes below as a reference for implementers:

| Hash function     |   Rate / block size (bytes)   |   Length of output (bytes)    |
|---                |---                            |---                            |
| SHA3-256          | 136                           | 32                            |
| SHA3-384          | 104                           | 48                            |
| SHA3-512          |  72                           | 64                            |
| SHA-256           |  64                           | 32                            |
| SHA-384           | 128                           | 48                            |
| SHA-512           | 128                           | 64                            |
| BLAKE2b           | 128                           | 64                            |
| BLAKE2s           |  64                           | 32                            |

We do not provide guidance for hashes with outputs smaller than 32 bytes.


## Worked Examples

To assist implementers with development, we include two worked examples below: one for SequenceHash and one for SequenceMAC. These worked examples include all intermediate values.

### SequenceHash

For a hash function, we choose `H = SHA-256`, which gives us `b = 64` and `L = 32`. Recall that the function indicator for SequenceHash is `F = 2`.

The key value for SequenceHash is fixed as a zero-length bytestring, and we'll use an empty customization string to match. For inputs, we'll use `I_0 = ''` (that is, an empty bytestring), `I_1 = 01`, `I_2 = 0202`, and `I_3 = 030303`.

This gives us:

```
EncodeMSBF(len(K)) =    00000000000000000000000000000000
EncodeMSBF(len(S)) =    00000000000000000000000000000000
EncodeMSBF(F) =         00000000000000000000000000000002
EncodeMSBF(L) =         00000000000000000000000000000020
```

Deriving our key and customizer blocks, we get:

```
K' = Derive(K, SHA-256, 64) = Pad('', 64) =   00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
S' = Derive(S, SHA-256, 64) = Pad('', 64) =   00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

The inputs encode to:

```
Encode(I_0)     =   00000000000000000000000000000000
Encode(I_1)     =   0100000000000000000000000000000001
Encode(I_2)     =   020000000000000000000000000000000202
Encode(I_3)     =   03000000000000000000000000000000030303
EncodeMSBF(n)   =   00000000000000000000000000000004
```

Computing the inner header block, we have:

```
HDR_I = Pad(5345514853485f49                    ||
            00000000000000000000000000000002    ||
            00000000000000000000000000000000, 64) = 
    5345514853485f490000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000
```

The outer header block is:

```
HDR_O = Pad(5345514853485f4f                    ||
            00000000000000000000000000000002    ||
            00000000000000000000000000000000    ||
            00000000000000000000000000000000, 64) = 
    5345514853485f4f0000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000
```

```
H(
    5345514853485f4f0000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000    ||      # Outer header block
    00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000    ||      # Customizer block
    00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000    ||      # Key block
    00000000000000000000000000000004                                                                                                    ||      # Item count
    00000000000000000000000000000020                                                                                                    ||      # Output length
    H(
        5345514853485f490000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000    ||  # Inner header block
        00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000    ||  # Key block
        00000000000000000000000000000000                                                                                                    ||  # Input 0 (encoded)
        0100000000000000000000000000000001                                                                                                  ||  # Input 1 (encoded)
        020000000000000000000000000000000202                                                                                                ||  # Input 2 (encoded)
        03000000000000000000000000000000030303                                                                                                  # Input 3 (encoded)
    )
)
```

Computing the inner hash, we get:

```
H(
    5345514853485f490000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000 ||
    00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 ||
    00000000000000000000000000000000 ||
    0100000000000000000000000000000001 ||
    020000000000000000000000000000000202 ||
    03000000000000000000000000000000030303
)
        = 5fddec134eb7c02acf9aca2afe8f5c529267958713588f3ebb3543c9788cdc28
```

Substituting into the outer hash, we get:

```
H(
    5345514853485f4f0000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000 ||
    00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 ||
    00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 ||
    00000000000000000000000000000004 ||
    00000000000000000000000000000020 ||
    5fddec134eb7c02acf9aca2afe8f5c529267958713588f3ebb3543c9788cdc28
)
        = 1339fb8e990da89ef98d7d8e7521f42d61566cc0b5388702b142cb57f02a4912
```

This gives us `SequenceHash(SHA-256, S; I_0, I_1, I_2, I_3) = 1339fb8e990da89ef98d7d8e7521f42d61566cc0b5388702b142cb57f02a4912`.


### SequenceMAC

As above, we choose `H = SHA-256`, which gives us `b = 64` and `L = 32`. Recall that the function indicator for SequenceMAC is `F = 1`.

For a key, we will take the 32-byte string `K = 27ece6764c77eb17e28a4031878198f37ce95207205fba8671390c8d7449dc91`. We will use four-byte all-zero customizer: `S = 00000000`. Note that `S` is NOT an empty customizer; it is a bytestring of length 4.

This gives us:

```
EncodeMSBF(len(K)) =    00000000000000000000000000000020
EncodeMSBF(len(S)) =    00000000000000000000000000000004
EncodeMSBF(F) =         00000000000000000000000000000001
EncodeMSBF(L) =         00000000000000000000000000000020
```

Computing the derived key and customizer blocks, we get:

```
K' = Derive(K, SHA-256, 64) = Pad(K, 64) = 27ece6764c77eb17e28a4031878198f37ce95207205fba8671390c8d7449dc910000000000000000000000000000000000000000000000000000000000000000
S' = Derive(S, SHA-256, 64) = Pad(S, 64) =    00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

We will use inputs `I_0 = 74aee83f30db3fd88d6e31ad41710cb8d9a5dd01aad1d1` (23 bytes long), `I_1 = f1ed6e58d442903e34571544a8af4f49e86790417916f538746911edbbd34fb9` (32 bytes), and `I_2 = bd121635c5c732` (7 bytes). Encoding these inputs and our input count `n = 3`, we get:

```
Encode(I_0)     =   1700000000000000000000000000000074aee83f30db3fd88d6e31ad41710cb8d9a5dd01aad1d1
Encode(I_1)     =   20000000000000000000000000000000f1ed6e58d442903e34571544a8af4f49e86790417916f538746911edbbd34fb9
Encode(I_2)     =   07000000000000000000000000000000bd121635c5c732
EncodeMSBF(n)   =   00000000000000000000000000000003
```

Computing the inner header block, we have:

```
HDR_I = Pad(5345514853485f49 ||
            00000000000000000000000000000001 ||
            00000000000000000000000000000020, 64) = 
    5345514853485f490000000000000000000000000000000100000000000000000000000000000020000000000000000000000000000000000000000000000000
```

The outer header block is:

```
HDR_O = Pad(5345514853485f4f ||
            00000000000000000000000000000001 ||
            00000000000000000000000000000004 ||
            00000000000000000000000000000020, 64) = 
    5345514853485f4f0000000000000000000000000000000100000000000000000000000000000004000000000000000000000000000000200000000000000000
```

Putting these together, we get:

```
H(
    5345514853485f4f0000000000000000000000000000000100000000000000000000000000000004000000000000000000000000000000200000000000000000    ||      # Outer header block
    00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000    ||      # Customizer block
    27ece6764c77eb17e28a4031878198f37ce95207205fba8671390c8d7449dc910000000000000000000000000000000000000000000000000000000000000000    ||      # Key block
    00000000000000000000000000000003    ||                                                                                                      # Item count
    00000000000000000000000000000020    ||                                                                                                      # Output length
    H(
        5345514853485f490000000000000000000000000000000100000000000000000000000000000020000000000000000000000000000000000000000000000000    ||  # Inner header block
        27ece6764c77eb17e28a4031878198f37ce95207205fba8671390c8d7449dc910000000000000000000000000000000000000000000000000000000000000000    ||  # Key block
        1700000000000000000000000000000074aee83f30db3fd88d6e31ad41710cb8d9a5dd01aad1d1  ||                                                      # Input 0 (encoded)
        20000000000000000000000000000000f1ed6e58d442903e34571544a8af4f49e86790417916f538746911edbbd34fb9    ||                                  # Input 1 (encoded)
        07000000000000000000000000000000bd121635c5c732                                                                                          # Input 2 (encoded)
    )
)
```

Computing the inner hash, we get:

```
H(
    5345514853485f490000000000000000000000000000000100000000000000000000000000000020000000000000000000000000000000000000000000000000    ||
    27ece6764c77eb17e28a4031878198f37ce95207205fba8671390c8d7449dc910000000000000000000000000000000000000000000000000000000000000000    ||
    1700000000000000000000000000000074aee83f30db3fd88d6e31ad41710cb8d9a5dd01aad1d1  ||
    20000000000000000000000000000000f1ed6e58d442903e34571544a8af4f49e86790417916f538746911edbbd34fb9    ||
    07000000000000000000000000000000bd121635c5c732)
        = 05a03dee856957821eb9c345835138af3bc3b8b01802effd1dfb477bff49f5c7
```

Our final hash computation simplifies to:

```
H(
    5345514853485f4f0000000000000000000000000000000100000000000000000000000000000004000000000000000000000000000000200000000000000000    ||
    00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000    ||
    27ece6764c77eb17e28a4031878198f37ce95207205fba8671390c8d7449dc910000000000000000000000000000000000000000000000000000000000000000    ||
    00000000000000000000000000000003    ||
    00000000000000000000000000000020    ||
    05a03dee856957821eb9c345835138af3bc3b8b01802effd1dfb477bff49f5c7)
            = 73440d6f3fcf4900428ee2e80c5b9bce04dd208dce14b892e6a0e220d2deb658
```

This gives us `SequenceMAC(SHA-256, K, S; I_0, I_1, I_2) = 73440d6f3fcf4900428ee2e80c5b9bce04dd208dce14b892e6a0e220d2deb658`.
