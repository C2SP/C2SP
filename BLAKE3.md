# The BLAKE3 Hashing Framework

[c2sp.org/BLAKE3](c2sp.org/BLAKE3)


## 1. Introduction

This document specifies BLAKE3, a cryptographic hashing primitive
designed to be fast and highly parallelizable. 
Apart from general-purpose hashing, BLAKE3 can realize the following
cryptographic functionalities:

* Extendable-output function (XOF)
* Key derivation function (KDF)
* Pseudorandom function (PRF)
* Message authentication code (MAC)

[BLAKE3][repo] was designed by Jack O'Connor, Jean-Philippe Aumasson,
Samuel Neves, and Zooko Wilcox-O'Hearn. BLAKE3 is an evolution from
its predecessors [BLAKE](https://aumasson.jp/blake/) (a SHA-3
competition finalist) and [BLAKE2](https://blake2.net) (RFC 7693).
BLAKE2 is widely used in open-source and proprietary software.  For
example, the Linux kernel uses BLAKE2 in its cryptographic pseudorandom
generator, and the WireGuard secure tunnel protocol uses BLAKE2 for
hashing and keyed hashing.

BLAKE3 was designed to be as secure as BLAKE2 yet considerably faster,
thanks to

1. A compression function with a reduced number of rounds, and
2. A tree-based mode allowing implementations to leverage parallel
processing.

BLAKE3 takes advantage of multi-thread and multi-core processing, as
well as the single-instruction multiple-data (SIMD) features of
modern processor architectures.

At the time of its publication, BLAKE3 was demonstrated to be
approximately five times faster than BLAKE2 when hashing 16 kibibyte
messages using a single thread on CPUs supporting AVX-512.  When using
multiple threads and hashing large messages, BLAKE3 can be more than
twenty times faster than BLAKE2.

### 1.1.  Hashing Modes

BLAKE3 can instantiate multiple cryptographic primitives, to offer a
simpler and more efficient alternative to dedicated legacy modes and
algorithms. These primitives include:

* **Unkeyed hashing (`hash`)**:  This is the general-purpose hashing
  mode, taking a single input of up to 2<sup>64</sup> - 1 bytes. BLAKE3
  in this mode can be used whenever a preimage- or collision-resistant
  hash function is needed, and to instantiate random oracles in
  cryptographic protocols. For example, BLAKE3 can replace SHA-3, as
  well as any SHA-2 instance, in applications such as digital
  signatures.

* **Keyed hashing (`keyed_hash`)**:  The keyed mode takes a 32-byte key
  in addition to the input.  BLAKE3 in this mode can be used whenever a
  pseudorandom function (PRF) or message authentication code (MAC) is
  needed.  For example, keyed BLAKE3 can replace HMAC instances.

* **Key derivation (`derive_key`)**:  The key derivation mode takes two
  inputs, a context string and key material, each of up to
  2<sup>64</sup> - 1 bytes.  BLAKE3 in this mode can be used whenever a
  key derivation function (KDF) is needed.  For example, BLAKE3 in key
  derivation mode can replace HKDF. The context string in this mode
  should be hardcoded, globally unique, and application-specific.

All modes return a 32-byte output by default, but they can produce up
to 2<sup>64</sup> - 1 output bytes. This allows the `hash` mode to be
used as an extendable-output-function (XOF) and the `keyed_hash` mode
to be used as a deterministic random bit generator (DRBG).

### 1.2. Security Considerations

BLAKE3 with an output of at least 32 bytes offers a security level of at
least 128 bits for all its security goals, as long as its core algorithm
is cryptographically safe. This algorithm is based on that of the
original BLAKE (published in 2008 and scrutinized throughout the SHA-3
competition), and is itself a variant of the core algorithm of the
ChaCha stream cipher, an established cipher that is standardized and
used in countless applications such as TLS and SSH.

BLAKE3 may be used in any of the modes described in this document to
provide cryptographically secure hashing functionality.  

BLAKE3 must not be used as a password-based hash function or
password-based key derivation function, functionalities for which
dedicated algorithms must be used, such as Argon2. 


### 1.3. Tree Hashing Overview

BLAKE3 processes input data according to a binary tree structure: 

1. It splits its input into 1024-byte chunks, processing each chunk
independently of the other chunks, using a compression function
iterating over each of the 16 consecutive 64-byte blocks of a chunk.

2. From the hash of each chunk, it builds a binary hash tree to compute
the root of the tree, which determines the BLAKE3 output.

In the simplest case, there is only one chunk.  In this case, this
node is seen as the tree's root and its output determines BLAKE3's
output.  If the number of chunks is a power of 2, the binary tree is
a complete tree and all leaves are at the same level.  If the number
of chunks is not a power of 2, not all chunks will be at the same
level of the tree.


## 2. Definitions

### 2.1. Word Size and Endianness

BLAKE3 works with 32-bit words and arrays thereof.
Array indexing starts at zero: the first element of an n-element array
`v` is `v[0]` and the last one is `v[n - 1]`.  The sequence of all
elements is denoted by `v[0..n-1]`.

Byte streams are interpreted as words in little-endian order,
with the least significant byte first. Consider for example this
sequence of eight bytes:


```
   x = 0x01 0x23 0x45 0x67 0x89 0xab 0xcd 0xef
```

When interpreted as a 32-bit word from the beginning memory address, `x`
contains two 32-bit words `x[0]` and `x[1]`, respectively equal to
0x67452301 and 0xefcdab89 in hexadecimal, or 1732584193 and 4023233417
in decimal.


### 2.2. Initial Value (IV)

The initial value (IV) of BLAKE3 is the same as the SHA-256 IV, namely the
8-word `IV[0..7]`:

```
   0x6a09e667
   0xbb67ae85
   0x3c6ef372
   0xa54ff53a
   0x510e527f
   0x9b05688c
   0x1f83d9ab
   0x5be0cd19
```

This IV is the initial chaining value of BLAKE3 when no key is
used.  Otherwise the 256-bit key is the initial chaining value.

This IV is also used as part of the compression function, where the
first four words, `IV[0..3]` are copied into the 16-word local initial
state, at positions `v[8..11]`.


### 2.3.  Message Word Permutation

BLAKE3 uses the following permutation of the 16 indices (0 to 15):

```
   0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15
   2,  6,  3, 10,  7,  0,  4, 13,  1, 11, 12,  5,  9, 14, 15,  8
```

That is, after applying the permutation to an array `v[0..15]`
consisting of elements `v[0], v[1], v[2], ..., v[15]`, the permuted
array shall consist of elements `v[2], v[6], v[3], ..., v[8]`.


### 2.4.  Compression Function Flags

The compression function of BLAKE3 uses a set of flags to
domain-separate different types of inputs.  These flags are defined as
follows:

* `CHUNK_START` (0x01):  Set for the first block of each chunk.

* `CHUNK_END` (0x02):  Set for the last block of each chunk.  If a chunk
  contains only one block, then both `CHUNK_START` and `CHUNK_END` are
  set.

* `PARENT` (0x04):  Set for parent nodes (non-chunk nodes).

* `ROOT` (0x08):  Set for the last compression of the root node.  If the
  root is a parent node, this is in addition to `PARENT`.  If the root
  is a chunk (the only chunk), this is in addition to `CHUNK_END.`

* `KEYED_HASH` (0x10):  Set for all compressions in the `keyed_hash` mode.

* `DERIVE_KEY_CONTEXT` (0x20):  Set for all compressions of the context
  string in the `derive_key` mode.

* `DERIVE_KEY_MATERIAL` (0x40):  Set for all compressions of the input
  (key material) in the `derive_key` mode.

If two or more flags are set, then all their respective bits must
appear in the `flags` compression function input.  This combination may
be implemented as an OR, XOR, or integer addition between the flags.
For example, if `CHUNK_START` and `KEYED_HASH` are set, then the flags
input word will be the 32-bit word 0x00000011, where `0x11 = 0x10 |
0x01 = 0x10 ^ 0x01 = 0x10 + 0x01`.


## 3.  Compression Function

BLAKE3 uses the compression function when processing chunks, when
computing parent nodes within its tree, and when producing output
bytes from the root node(s).

### 3.1.  Compression Function Input Values

These variables are used in the algorithm description.

* `h[0..7]`:  The hash chaining value, 8 words of 32 bits each.

* `m[0..15]`:  The message block processed, 16 words of 32 bits each.

* `t[0..1]`:  A 64-bit counter whose lower-order 32-bit word is `t[0]` and
  higher-order 32-bit word is `t[1]`.

* `len`:  A 32-bit word encoding the number of input bytes in the
  message block, at most 64.  `len` is equal to 64 minus the number of
  padding bytes, which are filled with zeros (0x00).

* `flags`:  A 32-bit word encoding the flags set for a given compression
  function call.


### 3.2.  Quarter-Round Function G

The `G` function mixes two input words `x` and `y` into four words indexed
by `a`, `b`, `c`, and `d` in the working array `v[0..15]`.  The full modified
array is returned.

```
           FUNCTION G( v[0..15], a, b, c, d, x, y )
           |
           |   v[a] := (v[a] + v[b] + x) mod 2**32
           |   v[d] := (v[d] ^ v[a]) >>> 16
           |   v[c] := (v[c] + v[d])     mod 2**32
           |   v[b] := (v[b] ^ v[c]) >>> 12
           |   v[a] := (v[a] + v[b] + y) mod 2**32
           |   v[d] := (v[d] ^ v[a]) >>> 8
           |   v[c] := (v[c] + v[d])     mod 2**32
           |   v[b] := (v[b] ^ v[c]) >>> 7
           |
           |   RETURN v[0..15]
           |
           END FUNCTION.
```


### 3.3.  Compression Function Processing

BLAKE3's compression function takes as input an 8-word chaining value
`h`, a 16-word message block `m`, a 2-word counter `t`, a data length
word `len`, and a
`flags` word (as a bit field encoding flags).

BLAKE3's compression must do exactly 7 rounds, which are numbered 0 to 6
in the pseudocode below.  Each round includes 8 calls to the `G`
function.


```
       FUNCTION BLAKE3_COMPRESS( h[0..7], m[0..15], t, len, flags )
       |
       |   // Initialize local 16-word array v[0..15]
       |   v[0..7] := h[0..7]              // 8 words from the state.
       |   v[8..11] := IV[0..3]            // 4 words from the IV.
       |
       |   v[12] :=  t[0]                  // Low word of the counter.
       |   v[13] :=  t[1]                  // High word of the counter.
       |   v[14] :=  len                   // Application data length.
       |   v[15] :=  flags                 // Flags.
       |
       |   // Cryptographic mixing
       |   FOR i = 0 TO 6 DO               // 7 rounds.
       |   |
       |   |   v := G( v, 0, 4,  8, 12, m[ 0], m[ 1] )
       |   |   v := G( v, 1, 5,  9, 13, m[ 2], m[ 3] )
       |   |   v := G( v, 2, 6, 10, 14, m[ 4], m[ 5] )
       |   |   v := G( v, 3, 7, 11, 15, m[ 6], m[ 7] )
       |   |
       |   |   v := G( v, 0, 5, 10, 15, m[ 8], m[ 9] )
       |   |   v := G( v, 1, 6, 11, 12, m[10], m[11] )
       |   |   v := G( v, 2, 7,  8, 13, m[12], m[13] )
       |   |   v := G( v, 3, 4,  9, 14, m[14], m[15] )
       |   |
       |   |   PERMUTE(m)                  // Apply the permutation.
       |   |
       |   END FOR
       |
       |   // Compute the output state (untruncated)
       |   FOR i = 0 TO 7 DO
       |   |   v[i] := v[i] ^ v[i + 8]
       |   |   v[i + 8] := v[i + 8] ^ h[i]
       |   END FOR.
       |
       |   RETURN v
       |
       END FUNCTION.
```


When processing chunks and parent nodes below the root, the output is
always truncated to the first 8 words, `v[0..7]`.  When computing the
output value, all 16 words may be used.


## 4.  Tree Mode of Operation

The following describes BLAKE3's tree mode of operation, first
specifying the processing of input data as chunks in section 4.2,
then describing how the binary hash tree structure is formed for a
given number of chunks in section 4.3.  Finally, section 4.4
describes how BLAKE3 can produce an output of arbitrary length
without committing to a length when processing starts.

### 4.1.  The 8-word Key

Each hashing mode uses an 8-word "key" for some of the inputs `h`
below.  In the unkeyed hashing mode (`hash`), the key is defined to be
`IV`.  In the keyed hashing mode (`keyed_hash`), the caller provides a
32-byte key parameter, and that parameter is split into 8 little-endian
words.

The key derivation mode (`derive_key`) operates in two phases, similar
to a `hash` followed by a `keyed_hash`, but setting different flags. In
the first phase (`DERIVE_KEY_CONTEXT`), the key is defined to be `IV`,
and the message is the context string.  In the second phase
(`DERIVE_KEY_MATERIAL`), the key is the truncated output of the first
phase, and the message is the key material.

### 4.2.  Chunk Processing

BLAKE3's chunk processing divides the BLAKE3 input into 1024-byte
chunks, which will be leaves of a binary tree.  If the input byte
length is not a multiple of 1024, the last chunk is short.  The last
chunk is empty if and only if the input is empty.

Chunks are divided into 64-byte blocks.  If the input byte length is
not a multiple of 64, the last block is short.  The last block is
empty if and only if the input is empty.  Short or empty blocks are
padded with zeros (0x00) to be 64 bytes.

Each chunk is processed by iterating the compression function
(1024/64 = 16 times for a full 1024-byte chunk) to process the
64-byte blocks, each parsed as 16 32-bit little-endian words.

Compression function input arguments are set as follows:

* `h[0..7]`: For the first block of a chunk, this is the 8-word key
  defined above.  For subsequent blocks, this is the truncated output of
  the compression of the previous block.

* `m[0..15]`: This is the block processed by the compression function.

* `t[0..1]`: The counter `t` for each block is the chunk index, that is, 0
  for all blocks in the first chunk, 1 for all blocks in the second
  chunk, and so on.

* `len`: This word is the block length, or the number of data bytes in the
  block, which is 64 for all blocks except possibly the last block of
  the last chunk.

* `flags`: This word is set as follows: The first block of each chunk sets
  the `CHUNK_START` flag, and the last block of each chunk sets the
  `CHUNK_END` flag.  If a chunk contains only one block, that block sets
  both `CHUNK_START` and `CHUNK_END`.  If a chunk is the root of its tree,
  the last block of that chunk also sets the `ROOT` flag.  Multiple flags
  may thus be set.


### 4.3.  Binary Tree Processing

From the chunk processing of input data, BLAKE3 computes its output
following a binary hash tree (a.k.a.  Merkle tree) structure.  Parent
nodes process 64-byte messages that consist of the concatenation of
two 32-byte hash values from child nodes (chunk nodes of other parent
nodes).  Processing such a 64-byte message requires only one call to
the compression function.

#### 4.3.1. Parent Nodes Inputs

The compression function used by parent nodes uses the following
arguments:

* `h[0..7]`:  This is the 8-word key defined above.

* `m[0..15]`:  This is the 64-byte block consisting of the concatenated
      32-byte output of the two child nodes.

* `t[0..1]`:  The counter t is set to zero (0).

* `len`:  The block length is set to 64.

* `flags`:  The `PARENT` flag is set for all parent nodes.  If a parent is
      the root of the tree, then it also sets the `ROOT` flag (and keeps
      the `PARENT` flag).  Parent nodes never set `CHUNK_START` and
      `CHUNK_END`.  The mode flags (`KEYED_HASH`, `DERIVE_KEY_CONTEXT`,
      `DERIVE_KEY_MATERIAL`) must be set for a parent node when operating
      in the respective modes.

#### 4.3.2. Incomplete Trees

When the number of chunks is not a power of 2 (that is, when the binary
tree is not complete), the tree structure is created according to the
following rules:

*  If there is **only one chunk**, that chunk is the root node and only
   node of the tree.  Otherwise, the chunks are assembled with parent
   nodes, each parent node having exactly two children.

*  **Left subtrees** are full, that is, each left subtree is a complete
   binary tree, with all its chunks at the same depth, and a number of
   chunks that is a power of 2.

*  **Left subtrees** are big, that is, each left subtree contains a
   number of chunks greater than or equal to the number of chunks in its
   sibling right subtree.

The root of the tree determines the final hash output.  By default, the
BLAKE3 output is the 32-byte output of the root node (that is, the final
values of `v[0..7]` in the compression function).  Output of up to 64
bytes is formed by taking as many bytes as required from the final
`v[0..15]` of the root's compression function.  See Section 4.4 for the
case of output values larger than 64 bytes.

### 4.4.  Extendable Output

BLAKE3, in any of its three modes, can produce outputs of any byte
length up to 2<sup>64</sup> - 1.  This is done by repeating the root
compression with incrementing values of the counter t.  The results of
these repeated root compressions are then concatenated to form the
output, possibly truncating the last one.

## 5.  Implementation Considerations

Detailed implementation and optimization guidelines are given in
Section 5 of the [BLAKE3 paper][paper] This section providers a brief
overview of these, as a starting point for implementers, covering the
most salient points.

Optimized implementations of BLAKE3 in the C and Rust languages are
available in the [BLAKE3 repository][repo]. These include parallel
implementations leveraging multi-threading and different SIMD
processing technologies.


### 5.1.  Incremental Hashing Implementation

BLAKE3 may be implemented by defining an application programming
interface (API) allowing for incremental hashing, that is, where the
caller provides input data via multiple repeated calls to an "update"
function, as opposed to a single call providing all the input data.
Such an API typically consists of an "init" function call to initialize
an internal context state, followed by a series of "update" function
calls, eventually followed by a "finalize" function call that that
returns the output.

To implement incremental hashing, an implementation must maintain an
internal state, which must keep track of the state of the current chunk
(if any) and of chaining values of the tree in formation.  A stack data
structure may be used for this purpose, as proposed in Section 5.1 of
[BLAKE3].


### 5.2.  Compression Function Implementation

In the compression function, the first four calls to `G` may be computed
in parallel.  Likewise, the last four calls to `G` may be computed in
parallel.  A parallel implementation of the compression function may
leverage single-instruction multiple-date (SIMD) processing, as
described in Section 5.3 of the [BLAKE3 paper][paper].

The permutation of words may be implemented by pre-computing the indices
corresponding to 0, 1, 2, ..., 7 iterations of the permutation, and then
applying each of these 7 permutations to the initial message at each of
the 7 rounds.  These 7 permutations would then be:

```
    0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15
    2,  6,  3, 10,  7,  0,  4, 13,  1, 11, 12,  5,  9, 14, 15,  8
    3,  4, 10, 12, 13,  2,  7, 14,  6,  5,  9,  0, 11, 15,  8,  1
   10,  7, 12,  9, 14,  3, 13, 15,  4,  0, 11,  2,  5,  8,  1,  6
   12, 13,  9, 11, 15, 10, 14,  8,  7,  2,  5,  3,  0,  1,  6,  4
    9, 14, 11,  5,  8, 12, 15,  1, 13,  3,  0, 10,  2,  6,  4,  7
   11, 15,  5,  0,  1,  9,  8,  6, 14, 10,  2, 12,  3,  4,  7, 13
```

### 5.3.  Multi-Threaded Implementation

In addition to the potential parallel computing of the compression
function internals via SIMD processing, BLAKE3 can benefit from
multi-threaded software implementation.  Different approaches may be
implemented, the performance-optimal one depending on the expected
input data length.  Section 5.2 in the [BLAKE3 paper][paper] provides
further guidelines to implementers.


### 5.4.  Extendable Output Implementation

Because the repeated root compressions differ only in the value of `t`,
the implementation can execute any number of them in parallel.  The
caller can also adjust `t` to seek to any point in the output stream.  For
example, computing the third 64-byte block of output (that is, the last
64 bytes of a 192-byte output) does not require the computation of the
first 128 bytes.

BLAKE3 does not domain separate outputs of different lengths: shorter
outputs are prefixes of longer ones.  The caller can extract as much
output as needed, without knowing the final length in advance.


## Appendix: Test Values

We provide execution traces for simple examples of BLAKE3 hashing. More
complex test cases can be obtained from the [reference implementation]
and its [test vectors].

[reference implementation]: https://github.com/BLAKE3-team/BLAKE3/tree/master/reference_impl
[test vectors]: https://github.com/BLAKE3-team/BLAKE3/blob/60ff2eafed63b29ed1622bb6330e640c22c683ff/test_vectors/test_vectors.json

### `hash` of a Single Block

In this first example, BLAKE3 in the `hash` mode processes the 4-byte message
"IETF", padded with 60 zero bytes to form a 64-byte block. Below we
show the execution trace, including compression function input and
output values, and intermediate values of the 7 compression function
rounds. Note that 4-byte words below are rendered without the "0x"
prefix but still in big-endian order. In particular, the ASCII codes
for "I" (0x49), "E" (0x45), "T" (0x54), and "F" (0x46) appear reversed
in the message block `m`, and the compress output and final hash value
are the same bytes with different endianness.

```
 == COMPRESS: CHUNK  1, BLOCK  0 ==

 h:
 6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19

 m:
 46544549 00000000 00000000 00000000 00000000 00000000 00000000 00000000
 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000

 t:
 00000000 00000000

 flags:
 0b

 after round 0:
 d7737c52 a0d29b6a d3b4f608 e20caed2 49091c17 b1abb189 961f03ba c3474f4e
 a7590324 9c110e95 f77c59cc b47c3370 9c1aed89 b7c28f82 bab6db43 e634ca3e

 after round 1:
 4cce55f2 9cdfa58b 297f68b4 887fd036 4e620c26 321af343 b8e634b0 72737ae9
 6f6ecf4a 628788fb df9428c1 a2c42d78 a51ddf7b 6cf97481 72dccb9c 1878acb8

 after round 2:
 8e99a713 bd202a18 d70c8d18 603ba3ad f411ae76 88ff9580 03db2909 a12e939f
 19b81233 69787f12 d2b0c5b7 52034613 21baaea8 84e5fe6d c8c96ae8 422a96d8

 after round 3:
 eeb6ec2a 22f4289a 64900193 d9f751b3 216a610d f5aadf41 ddf5584d ae312167
 c8f40fb3 97f06701 6eee4503 4827825d 3c59d243 473585da 90d24798 c5957f9d

 after round 4:
 11876617 4a71dc87 23a5b774 185e51fa a1ed35c0 729a3348 6da19311 9716237c
 f66bbb71 f303cf35 585dd137 e5c9c363 8b2b32ed 6add0d37 12b87a10 f96fde3e

 after round 5:
 02b010fc 345f4920 ce96e963 018a8afd c0e0faca 651d2baf 0b24a23d d1ffa8fc
 aa7de2ee d80796c0 ff96b6bd 7cfbf53a 292b8630 8d8e1a78 31c6cb9d b471de23

 after round 6:
 a4839e1a 064b478f bb47c942 3f4a0350 efd0bb79 61167ed0 356b01f5 b40f5364
 ba5d3c99 adadb369 9fcea12a f08a4ddf 7ba07e35 9e94d896 e3dfca24 568e0272

 compress output:
 1edea283 abe6f4e6 24896868 cfc04e8f 9470c54c ff82a646 d6b4cbd1 e2815116

 hash value:
 83a2de1ee6f4e6ab686889248f4ec0cf4cc5709446a682ffd1cbb4d6165181e2
```


### `keyed_hash` of Multiple Chunks

In this second example, BLAKE3 in the `keyed_hash` mode processes a
message composed of two 1024-byte chunks, the first consisting only of
0xaa bytes and the second consisting only of 0xbb bytes, using a
32-byte key consisting of only 0xcc bytes.  Below we show the execution
trace, including compression function input and output values for each
compression function: the 16 + 16 = 32 compressions of the two chunks,
and the compression of the root parent node. We only show the message
block for the first compression of a chunk, as all the subsequent
blocks hash the same block value (respectively, all 0xaa and all 0xbb
for the two chunks).  Likewise, we only show the counter value and
flags when they changes (the counter is, 0, 1, and 0 respectively for
the two chunks and for the root).  The `len` compression function
argument is always 64, and we omit it.  Chunks and blocks are numbered
from 0.


```
 == COMPRESS: CHUNK  0, BLOCK  0 ==

 h:
 cccccccc cccccccc cccccccc cccccccc cccccccc cccccccc cccccccc cccccccc

 m:
 aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa
 aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa

 t:
 00000000 00000000

 flags:
 11

 compress output:
 baa549b8 dea706e4 798b0aa9 544f7920 fc8e1726 b97cd19b 493e836a 91cac56b

 == COMPRESS: CHUNK  0, BLOCK  1 ==

 h:
 baa549b8 dea706e4 798b0aa9 544f7920 fc8e1726 b97cd19b 493e836a 91cac56b

 flags:
 10

 compress output:
 dcc8eee6 e2cea5b5 5ff3c247 e11308d2 bc77281c 5445017f c9561731 1300e3f9

 == COMPRESS: CHUNK  0, BLOCK  2 ==

 h:
 dcc8eee6 e2cea5b5 5ff3c247 e11308d2 bc77281c 5445017f c9561731 1300e3f9

 compress output:
 c9a030b5 9e370de1 762e7e79 671e218b 5cae980e 1988e543 7c2cc214 9e41c27f

 == COMPRESS: CHUNK  0, BLOCK  3 ==

 h:
 c9a030b5 9e370de1 762e7e79 671e218b 5cae980e 1988e543 7c2cc214 9e41c27f

 compress output:
 c19842fb 240f1f42 398d8fa5 a7f13935 d2c70e95 af05dcda 7029a16e f8ee91e8

 == COMPRESS: CHUNK  0, BLOCK  4 ==

 h:
 c19842fb 240f1f42 398d8fa5 a7f13935 d2c70e95 af05dcda 7029a16e f8ee91e8

 compress output:
 f9b7f73f 5f730ca0 4e9a9d4f cbb33329 95cc7bff ce4bcf1f 7f1d55bb b1484e9c

 == COMPRESS: CHUNK  0, BLOCK  5 ==

 h:
 f9b7f73f 5f730ca0 4e9a9d4f cbb33329 95cc7bff ce4bcf1f 7f1d55bb b1484e9c

 compress output:
 5fb55674 12ddc27e f481330c e6fbed3a 9a9ab905 1d23a7fa af95e6a9 2fc43b01

 == COMPRESS: CHUNK  0, BLOCK  6 ==

 h:
 5fb55674 12ddc27e f481330c e6fbed3a 9a9ab905 1d23a7fa af95e6a9 2fc43b01

 compress output:
 f4a22caa 7bfd6385 3b4f851a ddad3c1b 0be2b89c 9cac5085 aa2d60aa 245a58e3

 == COMPRESS: CHUNK  0, BLOCK  7 ==

 h:
 f4a22caa 7bfd6385 3b4f851a ddad3c1b 0be2b89c 9cac5085 aa2d60aa 245a58e3

 compress output:
 be0b5d38 2bc86413 e87b7127 8e616e88 53d77f04 714ac5c0 94c6bc67 46833b92

 == COMPRESS: CHUNK  0, BLOCK  8 ==

 h:
 be0b5d38 2bc86413 e87b7127 8e616e88 53d77f04 714ac5c0 94c6bc67 46833b92

 compress output:
 f2301e2c 43cf8b96 1f2fdf31 22949544 d561c502 b3bd97c8 3c9e0eb0 98f922f7

 == COMPRESS: CHUNK  0, BLOCK  9 ==

 h:
 f2301e2c 43cf8b96 1f2fdf31 22949544 d561c502 b3bd97c8 3c9e0eb0 98f922f7

 compress output:
 f010be56 93e3b9bb 2784704e 43058c38 bd00ccf5 4ecd501a eb472253 15789475

 == COMPRESS: CHUNK  0, BLOCK 10 ==

 h:
 f010be56 93e3b9bb 2784704e 43058c38 bd00ccf5 4ecd501a eb472253 15789475

 compress output:
 97b93bc4 368cf217 bb5255e5 29eaaf01 51119ef8 83a681b1 1247e464 3c211a4c

 == COMPRESS: CHUNK  0, BLOCK 11 ==

 h:
 97b93bc4 368cf217 bb5255e5 29eaaf01 51119ef8 83a681b1 1247e464 3c211a4c

 compress output:
 489377de a84ce607 615dc801 0abdce8d b8c62c73 2812c9b6 27f46f06 527ab15a

 == COMPRESS: CHUNK  0, BLOCK 12 ==

 h:
 489377de a84ce607 615dc801 0abdce8d b8c62c73 2812c9b6 27f46f06 527ab15a

 compress output:
 8b24d6ec 0fef6dc8 80f3a2bf 39980de6 ed40c8b6 231921d7 0ed6c3b8 216af5e9

 == COMPRESS: CHUNK  0, BLOCK 13 ==

 h:
 8b24d6ec 0fef6dc8 80f3a2bf 39980de6 ed40c8b6 231921d7 0ed6c3b8 216af5e9

 compress output:
 82305351 f39c3999 c4f58155 6033aecc c50d1a37 d2cd94e9 0fda6a32 783f75d3

 == COMPRESS: CHUNK  0, BLOCK 14 ==

 h:
 82305351 f39c3999 c4f58155 6033aecc c50d1a37 d2cd94e9 0fda6a32 783f75d3

 compress output:
 63e7e3be 04225085 80b70dfb 3abeec2f 03940104 81d8250a fe7c8027 0092e699

 == COMPRESS: CHUNK  0, BLOCK 15 ==

 h:
 63e7e3be 04225085 80b70dfb 3abeec2f 03940104 81d8250a fe7c8027 0092e699

 flags:
 12

 compress output:
 29262c25 7bd34920 9f5c3d18 bf3fc32b 3a10e594 9837aef0 67216d78 7384dda8

 == COMPRESS: CHUNK  1, BLOCK  0 ==

 h:
 cccccccc cccccccc cccccccc cccccccc cccccccc cccccccc cccccccc cccccccc

 m:
 bbbbbbbb bbbbbbbb bbbbbbbb bbbbbbbb bbbbbbbb bbbbbbbb bbbbbbbb bbbbbbbb
 bbbbbbbb bbbbbbbb bbbbbbbb bbbbbbbb bbbbbbbb bbbbbbbb bbbbbbbb bbbbbbbb

 t:
 00000001 00000000

 flags:
 11

 compress output:
 f8d2d7f6 da05998d f3e8d669 ea509854 a8640452 537101cf 3b74c8a7 c3140f9b

 == COMPRESS: CHUNK  1, BLOCK  1 ==

 h:
 f8d2d7f6 da05998d f3e8d669 ea509854 a8640452 537101cf 3b74c8a7 c3140f9b

 flags:
 10

 compress output:
 32bb9819 f7e708ff 2f025b74 eb3005f7 20ce66b9 1578615b b3fce09c 94a3223f

 == COMPRESS: CHUNK  1, BLOCK  2 ==

 h:
 32bb9819 f7e708ff 2f025b74 eb3005f7 20ce66b9 1578615b b3fce09c 94a3223f

 compress output:
 afe3cf08 158913a9 f53241f5 3eb8275f cdad0af5 fdb24fb7 acb6c848 5fed58e2

 == COMPRESS: CHUNK  1, BLOCK  3 ==

 h:
 afe3cf08 158913a9 f53241f5 3eb8275f cdad0af5 fdb24fb7 acb6c848 5fed58e2

 compress output:
 456318e4 9d40d864 5cb94c14 3975495a bea7d0f2 27093080 8f3b81ba 735a5e62

 == COMPRESS: CHUNK  1, BLOCK  4 ==

 h:
 456318e4 9d40d864 5cb94c14 3975495a bea7d0f2 27093080 8f3b81ba 735a5e62

 compress output:
 a4326ebd c7b57481 9836a9ea 8388a8fb 74fd982e dada4781 1e7fd411 d8538ea0

 == COMPRESS: CHUNK  1, BLOCK  5 ==

 h:
 a4326ebd c7b57481 9836a9ea 8388a8fb 74fd982e dada4781 1e7fd411 d8538ea0

 compress output:
 fad9c888 55228532 0eff7275 3ce3dd76 09292e60 a4808616 355b6abc 180f3f01

 == COMPRESS: CHUNK  1, BLOCK  6 ==

 h:
 fad9c888 55228532 0eff7275 3ce3dd76 09292e60 a4808616 355b6abc 180f3f01

 compress output:
 f72d8ed8 e18a1c97 dd37019d 2dcd3619 45d86a9a 669ecbd6 988d6e5e 239b094b

 == COMPRESS: CHUNK  1, BLOCK  7 ==

 h:
 f72d8ed8 e18a1c97 dd37019d 2dcd3619 45d86a9a 669ecbd6 988d6e5e 239b094b

 compress output:
 ddd825cb a63eccf2 711e1965 e762e7eb 10df5856 fe83880f 426243ab 17912393

 == COMPRESS: CHUNK  1, BLOCK  8 ==

 h:
 ddd825cb a63eccf2 711e1965 e762e7eb 10df5856 fe83880f 426243ab 17912393

 compress output:
 4d3a0cb8 b3fa6eb3 5562262c 21ecbe87 2cb06776 646d4444 917f3476 95dacdab

 == COMPRESS: CHUNK  1, BLOCK  9 ==

 h:
 4d3a0cb8 b3fa6eb3 5562262c 21ecbe87 2cb06776 646d4444 917f3476 95dacdab

 compress output:
 4e3c8403 172f2851 9174c228 a1a02b1c 1f9f5195 6e2ef47b 71103308 2cebea3a

 == COMPRESS: CHUNK  1, BLOCK 10 ==

 h:
 4e3c8403 172f2851 9174c228 a1a02b1c 1f9f5195 6e2ef47b 71103308 2cebea3a

 compress output:
 e90fa204 592a4848 b8c7badf 9afa2d5c f9f30477 3bc27906 dcdc8c12 8c57930b

 == COMPRESS: CHUNK  1, BLOCK 11 ==

 h:
 e90fa204 592a4848 b8c7badf 9afa2d5c f9f30477 3bc27906 dcdc8c12 8c57930b

 compress output:
 6d5b3ea9 288009bc 63d2fd33 f58ae27b d1cc9858 09c842b3 d45c69fd f7cf53ab

 == COMPRESS: CHUNK  1, BLOCK 12 ==

 h:
 6d5b3ea9 288009bc 63d2fd33 f58ae27b d1cc9858 09c842b3 d45c69fd f7cf53ab

 compress output:
 c398059d 89d3db73 1cf0fb5c 8b9fe830 544ecbb6 81767776 81cb99bb 5bb3e546

 == COMPRESS: CHUNK  1, BLOCK 13 ==

 h:
 c398059d 89d3db73 1cf0fb5c 8b9fe830 544ecbb6 81767776 81cb99bb 5bb3e546

 compress output:
 d228d203 4aa56614 e20eeb08 3a030c71 04a5e52c 680b1da3 a202d5e9 ff681705

 == COMPRESS: CHUNK  1, BLOCK 14 ==

 h:
 d228d203 4aa56614 e20eeb08 3a030c71 04a5e52c 680b1da3 a202d5e9 ff681705

 compress output:
 9bc8d417 c5934dc1 7cd704f3 293a98f7 acd5d444 c96af077 dfdb7ddb 4beed53e

 == COMPRESS: CHUNK  1, BLOCK 15 ==

 h:
 9bc8d417 c5934dc1 7cd704f3 293a98f7 acd5d444 c96af077 dfdb7ddb 4beed53e

 flags:
 12

 compress output:
 a1df18f4 c3cd10d0 7a695bb0 35f28871 c2e85b18 bf08c8ea d99162be 51be2388

 == COMPRESS: PARENT ==

 h:
 cccccccc cccccccc cccccccc cccccccc cccccccc cccccccc cccccccc cccccccc

 m:
 29262c25 7bd34920 9f5c3d18 bf3fc32b 3a10e594 9837aef0 67216d78 7384dda8
 a1df18f4 c3cd10d0 7a695bb0 35f28871 c2e85b18 bf08c8ea d99162be 51be2388

 t:
 00000000 00000000

 flags:
 1c

 compress output:
 3dabaf34 1697b337 844bdf42 fa3d2c86 35d5505c e39ce71b de24d93b 058d9f55

 hash value:
 34afab3d37b3971642df4b84862c3dfa5c50d5351be79ce33bd924de559f8d05
```

[repo]: https://github.com/BLAKE3-team/BLAKE3
[paper]: https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf
