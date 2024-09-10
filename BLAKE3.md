# The BLAKE3 Hashing Framework

[c2sp.org/BLAKE3](c2sp.org/BLAKE3)


This document specifies the cryptographic hashing primitive BLAKE3, a
secure algorithm designed to be fast and highly parallelizable.  Apart
from the standard hashing functionality, BLAKE3 can serve to realize the
following cryptographic functionalities: extendable- output function
(XOF), key derivation function (KDF), pseudo-random function (PRF), and
message authentication code (MAC).


## 1. Introduction

The [BLAKE3] cryptographic hash function was designed by Jack O'Connor,
Jean-Philippe Aumasson, Samuel Neves, and Zooko Wilcox- O'Hearn.  BLAKE3
is an evolution from its predecessors [BLAKE] and [BLAKE2][RFC7693].
BLAKE2 is widely used in open-source software and in proprietary
software.  For example, the Linux kernel (from version 5.17) uses BLAKE2
in its cryptographic pseudorandom generator, and the WireGuard secure tunnel protocol uses BLAKE2 for hashing and keyed hashing.

BLAKE3 was designed to be as secure as BLAKE2, yet considerably faster,
thanks to 1) a compression function with a reduced number of rounds, and
2) a tree-based mode allowing implementations to leverage parallel
processing.  BLAKE3 was designed to take advantage of multi- thread and
multi-core processing, as well as of single-instruction multiple-data
(SIMD) instructions of modern processor architectures.

At the time of its publication, BLAKE3 was demonstrated to be
approximately five times faster than BLAKE2 when hashing 16 kibibyte
messages and using a single thread.  When using multiple threads and
hashing large messages, BLAKE3 can be more than twenty times faster
than BLAKE2.

### 1.1.  Hashing Modes

BLAKE3 was also designed to instantiate multiple cryptographic
primitives, to offer a simpler and more efficient alternative to
dedicated legacy modes and algorithms.  These
primitives include:

* **Unkeyed hashing (hash)**:  This is the general-purpose hashing mode,
  taking a single input of arbitrary size.  BLAKE3 in this mode can be
  used whenever a preimage- or collision-resistant hash function is
  needed, and to instantiate random oracles in cryptographic protocols.
  For example, BLAKE3 can replace SHA-3, as well as any SHA-2 instance,
  in applications such as digital signatures.

* **Keyed hashing (keyed_hash)**:  The keyed mode takes a 32-byte key,
  in addition to the arbitrary size input.  BLAKE3 in this mode can be
  used whenever a pseudorandom function (PRF) or message authentication
  code (MAC) is needed.  For example, keyed BLAKE3 can replace HMAC
  instances.

* **Key derivation (derive_key)**:  The key derivation mode takes two
  input values, each of arbitrary size: a context string, and key
  material.  BLAKE3 in this mode can be used whenever a key derivation
  function (KDF) is needed.  For example, BLAKE3 in key derivation mode
  can replace HKDF.

Further, all 3 modes can produce an output of arbitrary size.  The hash
mode can thus be used as an extendable-output-function (XOF); the keyed
hash mode can thus be used as a deterministic random bit generator
(DRBG).  By default, each mode returns a 32-byte output.


Applications and use cases of BLAKE3 are further discussed in Section 6
in [BLAKE3].

### 1.2. Hashing Structure

We provide a high-level overview of BLAKE3's internal structure, and
introduce the associated terminology.

BLAKE3 processes input data according to a binary tree structure.  It
first splits its input into 1024-byte chunks, processing each chunk
independently of the other chunks, using a compression function
iterating over each of the 16 consecutive 64-byte blocks of a chunk.

From the hash of each chunk, a binary hash tree is built to compute
the root of the tree, which determines the BLAKE3 output.

In the simplest case, there is only one chunk.  In this case, this
node is seen as the tree's root and its output determines BLAKE3's
output.  If the number of chunks is a power of 2, the binary tree is
a complete tree and all leaves are at the same level.  If the number
of chunks is not a power of 2, not all chunks will be at the same
level (or layer) of the tree.

## 2. Definitions

### 2.1. Notations

   BLAKE3 performs operations on 32-bit words, and on arrays of words.
   Array indexing is zero-based; the first element of an n-element array
   "v" is v[0] and the last one is v[n - 1].  All elements is denoted by
   v[0..n-1].

   Byte (octet) streams are interpreted as words in little-endian order,
   with the least significant byte first.  Consider this sequence of
   eight hexadecimal bytes:


```
           x = 0x01 0x23 0x45 0x67 0x89 0xab 0xcd 0xef
```

   When interpreted as a 32-bit word from the beginning memory address,
   x contains two 32-bit words x[0] and x[1], respectively equal to
   0x67452301 and 0xefcdab89 in hexadecimal, or 1732584193 and
   4023233417 in decimal.

### 2.2. Initial Value (IV)

   The initial value (IV) of BLAKE3 is the same as SHA-256 IV, namely
   the 8-word IV[0..7]: 

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

   This IV is set to the initial chaining value of BLAKE3 when no key is
   used.  Otherwise the 256-bit key is set as the initial chaining
   value.

   This IV is also used as part of the compression function, where the
   first four words, IV[0..3] are copied into the 16-word local initial
   state, at positions v[8..11].


### 2.3.  Message Word Permutation

   BLAKE3 uses a permutation of the 16 indices (0 to 15).  This
   permutation must be following one, where the second line shows the
   index of the word move to the position indexed on the first line:

```
       0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15
       2,  6,  3, 10,  7,  0,  4, 13,  1, 11, 12,  5,  9, 14, 15,  8
```

   For example, after applying the permutation to an array v[0..15]
   consisting of elements v[0], v[1], ..., v[15], the permuted array
   shall consist of v[2] at the first position, v[6] at the second
   position, and so on.

### 2.4.  Compression Function Flags

   The compression function of BLAKE3 uses a set of flags to domain-
   separate different types of inputs.  These flags are defined as
   follows:

   CHUNK_START (0x01):  Set for the first block of each chunk.

   CHUNK_END (0x02):  Set for the last block of each chunk.  If a chunk
      contains only one block, then both CHUNK_START and CHUNK_END are
      set.

   PARENT (0x04):  Set for parent nodes (non-chunk nodes).

   ROOT (0x08):  Set for the last compression of the root node.  If the
      root is a parent node, this is in addition to PARENT.  If the root
      is a chunk (the only chunk), this is in addition to CHUNK_END.

   KEYED_HASH (0x10):  Set for all compressions in the keyed_hash mode.

   DERIVE_KEY_CONTEXT (0x20):  Set for all compressions of the context
      string in the derive_key mode.

   DERIVE_KEY_MATERIAL (0x40):  Set for all compressions of the input
      (key material) in the derive_key mode.

   If two or more flags are set, then all their respective bits shall
   appear in the flags compression function input.  This combination may
   be implemented as an XOR or integer addition between the flags.  For
   example, if CHUNK_START and KEYED_HASH are set, then the flags input
   word will be the 32-bit word 0x00000011, where 0x11 = 0x10 + 0x01 =
   0x10 ^ 0x01.


## 3.  Compression Function

   BLAKE3 uses the compression function when processing chunks, when
   computing parent nodes within its tree, and when producing output
   bytes from the root node(s).

### 3.1.  Compression Function Input Values

   These variables are used in the algorithm description.

   h[0..7]  The hash chaining value, 8 words of 32 bits.

   m[0..15]  The message block processed, 16 words of 32 bits.

   t[0..1]  A 64-bit counter whose lower-order 32-bit word is t[0] and
      higher-order 32-bit word is t[1].

   len  32-bit word encoding the number of application data bytes in the
      block, at most 64.  That is, len is equal to 64 minus the number
      of padding bytes, which are set to zero (0x00).

   flags  32-bit word encoding the flags defined for a given compression
      function call, see Section 2.5.

   (Artwork only available as (unknown type): No external link
   available, see draft-aumasson-blake3-00.html for artwork.)

### 3.2.  Quarter-Round Function G

   The G function mixes two input words x and y into four words indexed
   by a, b, c, and d in the working array v[0..15].  The full modified
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

   BLAKE3's compression function takes as input an 8-word state h, a
   16-word message m, a 2-word counter t, a data length word len, and a
   word flags (as a bit field encoding flags).

   BLAKE3's compression must do exactly 7 rounds, which are numbered 0
   to 6 in the pseudocode below.  Each round includes 8 calls to the G
   function.



```
       FUNCTION BLAKE3_COMPRESS( h[0..7], m[0..15], t, len, flags )
       |
       |   // Initialize local 16-word array v[0..15]
       |   v[0..7] := h[0..7]              // First half from state.
       |   v[8..11] := IV[0..3]            // Second half from IV.
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
       |   |   v := G( v, 3, 4,  9, 14, m[15], m[15] )
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
   always truncated to the first 8 words v[0..7].  When computing the
   output value, all 16 words may be used.


## 4.  Tree Mode of Operation

The following describes BLAKE3's tree mode of operation, first
specifying the processing of input data as chunks in Section 4.2,
then describing how the binary hash tree structure is formed for a
given number of chunks in Section 4.3.  Finally, Section 4.4
describes how BLAKE3 can produce an output of arbitrary length
without committing to a length when processing starts.

### 4.1.  The 8-word Key

Each hashing mode uses an 8-word "key" for some of the inputs h
below.  In the unkeyed hashing mode (hash), the key is defined to be
IV.  In the keyed hashing mode (keyed_hash), the caller provides a
32-byte key parameter, and that parameter is split into 8 little-
endian words.  The key derivation mode (derive_key) operates in two
phases: In the first phase (DERIVE_KEY_CONTEXT), the key is defined
to be IV.  In the second phase (DERIVE_KEY_MATERIAL), the key is the
truncated output of the first phase.

### 4.2.  Chunk Processing

BLAKE3's chunk processing divides the BLAKE3 input into 1024-byte
chunks, which will be leaves of a binary tree.  If the input byte
length is not a multiple of 1024, the last chunk is short.  The last
chunk is empty if and only if the input is empty.

Chunks are divided into 64-byte blocks.  If the input byte length is
not a multiple of 64, the last block is short.  The last block is
empty if and only if the input is empty.  Short or empty blocks are
padded with zeros to be 64 bytes.

Each chunk is processed by iterating the compression function
(1024/64 = 16 times for a full 1024-byte chunk) to process the
64-byte blocks, each parsed as 16 32-bit little-endian words.

Compression function input arguments are set as follows:

* h[0..7]  For the first block of a chunk, this is the 8-word key
      defined above.  For subsequent blocks, this is the truncated
      output of the compression of the previous block.

*   m[0..15]  This is the block processed by the compression function.

*   t[0..1]  The counter t for each block is the chunk index, that is, 0
      for all blocks in the first chunk, 1 for all blocks in the second
      chunk, and so on.

*   len  The block length is the number of data bytes in the block, which
      is 64 for all blocks except possibly the last block of the last
      chunk.

*   flag  The first block of each chunk sets the CHUNK_START flag (cf.
      Section 2.5), and the last block of each chunk sets the CHUNK_END
      flag.  If a chunk contains only one block, that block sets both
      CHUNK_START and CHUNK_END.  If a chunk is the root of its tree,
      the last block of that chunk also sets the ROOT flag.  Multiple
      flags may thus be set.

### 4.3.  Binary Tree Processing

From the chunk processing of input data, BLAKE3 computes its output
following a binary hash tree (a.k.a.  Merkle tree) structure.  Parent
nodes process 64-byte messages that consist of the concatenation of
two 32-byte hash values from child nodes (chunk nodes of other parent
nodes).  Processing such a 64-byte message requires only one call to
the compression function.

The compression function used by parent nodes thus uses the following
arguments:

* h[0..7]  This is the 8-word key defined above.

* m[0..15]  This is the 64-byte block consisting in the concatenated
      32-byte output of the two child nodes.

* t[0..1]  The counter t is set to zero (0).

* len  The block length is set to 64.

* flag  The PARENT flag is set for all parent nodes.  If a parent is
      the root of the tree, then it also sets the ROOT flag (and keeps
      the PARENT flag).  Parent nodes never set CHUNK_START and
      CHUNK_END.  The mode flags (KEYED_HASH, DERIVE_KEY_CONTEXT,
      DERIVE_KEY_MATERIAL) must be set for a parent node when operating
      in the respective modes.

When the number of chunks is not a power of 2 (that is, when the binary
tree is not complete), the tree structure is created according to the
following rules:

*  If there is only one chunk, that chunk is the root node and only
      node of the tree.  Otherwise, the chunks are assembled with parent
      nodes, each parent node having exactly two children.


*  Left subtrees are full, that is, each left subtree is a complete
      binary tree, with all its chunks at the same depth, and a number
      of chunks that is a power of 2.

*  Left subtrees are big, that is, each left subtree contains a
      number of chunks greater than or equal to the number of chunks in
      its sibling right subtree.

The implementation of this logic, especially regarding the assignment of
a chunk to a position in the tree, is discussed in Section 5.

The root of the tree determines the final hash output.  By default, the
BLAKE3 output is the 32-byte output of the root node (that is, the final
values of v[0..7] in the compression function).  Output of up to 64
bytes is formed by taking as many bytes as required from the final
v[0..15] of the root's compression function.  See Section 4.4 for the
case of output values larger than 64 bytes.

### 4.4.  Extendable Output

BLAKE3, in any of its three modes, can produce outputs of any byte
length up to 2<sup>64</sup> - 1.  This is done by repeating the root compression
with incrementing values of the counter t.  The results of these
repeated root compressions are then concatenated to form the output.

## 5.  Implementation Considerations

   Detailed implementation and optimization guidelines are given in
   Section 5 of [BLAKE3].  This section providers a brief overview of
   these, as a starting point to implementers, covering the most salient
   points.

### 5.1.  Incremental Hashing Implementation

BLAKE3 may be implemented using an application programming interface
(API) allowing for incremental hashing, that is, where the caller
provides input data via multiple repeated calls to an "update" function,
as opposed to a single call providing all the input data.  Such an API
typically consists of an "init" function call to initialize an internal
context state, followed by a series of "update" function calls,
eventually followed by a "finalize" function call that that returns the
output.


To implement incremental hashing, an implementation must maintain an
internal state, which must keep track of the state of the current chunk
(if any) and of chaining values of the tree in formation.  A stack data
structure may be used for this purpose, as proposed in Section 5.1 of
[BLAKE3].

### 5.2.  Compression Function Implementation

In the compression function, the first four calls to G may be computed
in parallel.  Likewise, the last four calls to G may be computed in
parallel.  A parallel implementation of the compression function may
leverage single-instruction multiple-date (SIMD) processing, as
described in Section 5.3 of [BLAKE3].

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

### 5.3.  Multi-Thread Implementation

In addition to the potential parallel computing of the compression
function internals via SIMD processing, BLAKE3 can benefit from
multi-threaded software implementation.  Different approaches may be
implemented, the performance-optimal one depending on the expected input
data length.  Section 5.2 in [BLAKE3] provides further guidelines to
implementers.

### 5.4.  Extendable Output Implementation

Because the repeated root compressions differ only in the value of t,
the implementation can execute any number of them in parallel.  The
caller can also adjust t to seek to any point in the output stream.  For
example, computing the third 64-byte block of output (that is, the last
64 bytes of a 192-byte output) does not require the computation of the
first 128 bytes.


BLAKE3 does not domain separate outputs of different lengths: shorter
outputs are prefixes of longer ones.  The caller can extract as much
output as needed, without knowing the final length in advance.


## 6.  Security Considerations

BLAKE3 with an output of at least 32 bytes targets a security level of
at least 128 bits for all its security goals.  BLAKE3 may be used in any
of the modes described in this document to provide cryptographically secure hashing functionality.  BLAKE3 must not be used as a password-based hash function or password-based key derivation function, functionalities for which dedicated algorithms must be used, such as Argon2 as defined in [RFC9106].

We refer the reader to [BLAKE3] for detailed cryptographic rationale and
security analysis of BLAKE3.

## 7.  References

   [BLAKE]    Aumasson, J-P., Meier, W., Phan, R C-W., and L. Henzen,
              "The Hash Function BLAKE", October 2008,
              <https://aumasson.jp/blake/>.

   [BLAKE2]   Aumasson, J-P., Neves, S., Wilcox-O'Hearn, Z., and C.
              Winnerlein, "BLAKE2: simpler, smaller, fast as MD5",
              January 2013, <https://www.blake2.net/>.

   [BLAKE3]   O'Connor, J., Aumasson, J-P., Neves, S., and Z. Wilcox-
              O'Hearn, "BLAKE3", January 2020,
              <https://github.com/BLAKE3-team/BLAKE3>.

   [RFC7693]  Saarinen, M-J. and J-P. Aumasson, "The BLAKE2
              Cryptographic Hash and Message Authentication Code (MAC)",
              RFC 7693, November 2015,
              <https://www.rfc-editor.org/rfc/rfc7693>.

   [RFC9106]  Biryukov, A-B., Dinu, D-D., Khovratovich, D-K., and S-J.
              Josefsson, "Argon2 Memory-Hard Function for Password
              Hashing and Proof-of-Work Applications", RFC 9106,
              September 2021, <https://www.rfc-editor.org/rfc/rfc9106>.

## Appendix A.  Implementation status

   Reference implementations of BLAKE3 in the C and Rust languages are
   available online at https://github.com/BLAKE3-team/BLAKE3/. These
   implementations include parallel implementations leveraging multi-
   threading and different SIMD processing technologies.

   At the time of writing, a number of prominent projects have
   integrated BLAKE3, due to its combination of security, speed, and
   versatility (see the README on https://github.com/BLAKE3-team/BLAKE3.

   For the sake of document size, these implementations are not copied
   into the present document.  However, they are expected to remain
   permanently available, for the foreseeable future.

## Appendix B.  Examples of BLAKE3 Computation

   We provide execution traces for simple examples of BLAKE3 hashing.
   More complex tests can be obtained from the reference source code.

### B.1.  Single Chunk in hash Mode

   In this first example, BLAKE3 in hash mode processes the 4-byte
   message "IETF", padded with 60 zero bytes to form a 64-byte block.
   Below we show the execution trace, including compression function
   input and output values, and showing intermediate values of the 7
   compression function rounds.


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


### B.2.  Multiple Chunks in keyed_hash Mode

In this second example, BLAKE3 in keyed hash mode processes a message
composed of two 1024-byte chunks, the first consisting only of 0xaa
bytes and the second consisting only of 0xbb bytes.  Below we show the
execution trace, including compression function input and output values
for each compression function: the 16 + 16 = 32 compressions of the two
chunks, and the compression of the root parent node.  We only show the
message block for the first compression of a chunk, as all the
subsequent blocks hash the same block value (respectively, all 0xaa and
all 0xbb for the two chunks).  Likewise, we only show the counter value
and flags when they changes (the counter is, 0, 1, and 0 respectively
for the two chunks and for the root).  The len compression function
argument is always 64, so we don't show it.  Chunks and blocks are
numbered from 0.


```
 == COMPRESS: CHUNK  0, BLOCK  0 ==

 h:
 6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19

 m:
 aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa
 aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa aaaaaaaa

 t:
 00000000 00000000

 flags:
 01

 compress output:
 db668896 8e557d4d 684294f4 ae36d8ae eaec1efd 5f5fc3ec d8d1abc5 10094488

 == COMPRESS: CHUNK  0, BLOCK  1 ==

 h:
 db668896 8e557d4d 684294f4 ae36d8ae eaec1efd 5f5fc3ec d8d1abc5 10094488

 flags:
 00

 compress output:
 68f7c3a8 8aaed76b f0decee2 d1b5993d 9564cba3 85b6c1ee baffea5b 0be671fb

 == COMPRESS: CHUNK  0, BLOCK  2 ==

 h:
 68f7c3a8 8aaed76b f0decee2 d1b5993d 9564cba3 85b6c1ee baffea5b 0be671fb

 compress output:
 e79aed24 3ad3caa0 199ce8a2 31155523 f9e84a64 e5bc14a9 9af2e334 9985ca87

 == COMPRESS: CHUNK  0, BLOCK  3 ==

 h:
 e79aed24 3ad3caa0 199ce8a2 31155523 f9e84a64 e5bc14a9 9af2e334 9985ca87

 compress output:
 35e722a9 0872b994 7a05884c 2968d0cd 08e92372 bc87969c d32d20e9 a5eb0ef6

 == COMPRESS: CHUNK  0, BLOCK  4 ==

 h:
 35e722a9 0872b994 7a05884c 2968d0cd 08e92372 bc87969c d32d20e9 a5eb0ef6

 compress output:
 0e618a8d 4c17b3a3 bf17a81a fae109b3 435486f5 7854e7ac 4b0e41f3 1b0a773a

 == COMPRESS: CHUNK  0, BLOCK  5 ==

 h:
 0e618a8d 4c17b3a3 bf17a81a fae109b3 435486f5 7854e7ac 4b0e41f3 1b0a773a

 compress output:
 689e8525 38241f4c 93c85386 8b89a303 200d341e cb4e0c76 0e4a9834 4ce07f14

 == COMPRESS: CHUNK  0, BLOCK  6 ==

 h:
 689e8525 38241f4c 93c85386 8b89a303 200d341e cb4e0c76 0e4a9834 4ce07f14

 compress output:
 ae51c883 e29a64b4 573eb2c4 324a0bb3 458f4c80 312ff7f1 9e194290 65c78a4d

 == COMPRESS: CHUNK  0, BLOCK  7 ==

 h:
 ae51c883 e29a64b4 573eb2c4 324a0bb3 458f4c80 312ff7f1 9e194290 65c78a4d

 compress output:
 082b24c1 4c09407c 9b80a3d9 ef173f4b f3f68d34 8afe0066 ed3c5f7e 83cf95d4

 == COMPRESS: CHUNK  0, BLOCK  8 ==

 h:
 082b24c1 4c09407c 9b80a3d9 ef173f4b f3f68d34 8afe0066 ed3c5f7e 83cf95d4

 compress output:
 fafc4be2 0bb87f3b ca34144b 1103ce02 d6cb4c49 1f20eab9 3593d1cf 3742859e

 == COMPRESS: CHUNK  0, BLOCK  9 ==

 h:
 fafc4be2 0bb87f3b ca34144b 1103ce02 d6cb4c49 1f20eab9 3593d1cf 3742859e

 compress output:
 51b45ba4 dd1b242a 002689c1 cfcd1997 073e3f21 3fe38ccb c59e4bcc 6c91298d

 == COMPRESS: CHUNK  0, BLOCK 10 ==

 h:
 51b45ba4 dd1b242a 002689c1 cfcd1997 073e3f21 3fe38ccb c59e4bcc 6c91298d

 compress output:
 dc832743 8edfe4dc 2434e697 17460dde 6dbf6b54 614f9af3 ca696833 6ee12fcd

 == COMPRESS: CHUNK  0, BLOCK 11 ==

 h:
 dc832743 8edfe4dc 2434e697 17460dde 6dbf6b54 614f9af3 ca696833 6ee12fcd

 compress output:
 86bda24a fc967396 ff8cf6db 017c4b90 ff72ef63 1bb302e4 0fe2b9cc 2a4470b7

 == COMPRESS: CHUNK  0, BLOCK 12 ==

 h:
 86bda24a fc967396 ff8cf6db 017c4b90 ff72ef63 1bb302e4 0fe2b9cc 2a4470b7

 compress output:
 bba75e83 28bac312 8a1565c6 66972f60 95ebb0a3 5ebf7a85 a4de1420 bbccd8ba

 == COMPRESS: CHUNK  0, BLOCK 13 ==

 h:
 bba75e83 28bac312 8a1565c6 66972f60 95ebb0a3 5ebf7a85 a4de1420 bbccd8ba

 compress output:
 37df0dd2 5521517f 2374fbfa 3811d80b 68f109d3 abf8cbf6 209efbdc 3432507b

 == COMPRESS: CHUNK  0, BLOCK 14 ==

 h:
 37df0dd2 5521517f 2374fbfa 3811d80b 68f109d3 abf8cbf6 209efbdc 3432507b

 compress output:
 996b6a0c e8dbdaeb da6a97ef 4391c111 12c223ba 3c092120 289dfbaa ed3ac2a5

 == COMPRESS: CHUNK  0, BLOCK 15 ==

 h:
 996b6a0c e8dbdaeb da6a97ef 4391c111 12c223ba 3c092120 289dfbaa ed3ac2a5

 flags:
 02

 compress output:
 c8d63b32 b1d9fecb dbf2dac7 7fba1e91 a71a614b 022d5eb6 43b88567 5fb98dbb

 == COMPRESS: CHUNK  1, BLOCK  0 ==

 h:
 6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19

 m:
 bbbbbbbb bbbbbbbb bbbbbbbb bbbbbbbb bbbbbbbb bbbbbbbb bbbbbbbb bbbbbbbb
 bbbbbbbb bbbbbbbb bbbbbbbb bbbbbbbb bbbbbbbb bbbbbbbb bbbbbbbb bbbbbbbb

 t:
 00000000 00000001


 flags:
 01

 compress output:
 4643287b d85bed11 5487228d a44a56de 4731717c cc6838ee 197aa105 db612375

 == COMPRESS: CHUNK  1, BLOCK  1 ==

 h:
 4643287b d85bed11 5487228d a44a56de 4731717c cc6838ee 197aa105 db612375

 flags:
 00

 compress output:
 e5be3ee8 6b8a6388 c6f1bb2d 96c4422a 69c5e773 08f62b86 8e0ac6ef 60053eb3

 == COMPRESS: CHUNK  1, BLOCK  2 ==

 h:
 e5be3ee8 6b8a6388 c6f1bb2d 96c4422a 69c5e773 08f62b86 8e0ac6ef 60053eb3

 compress output:
 f14e85f1 7e3dd3cd 21821aea 13a60dd9 ed703026 6d162747 f486ce97 3b802292

 == COMPRESS: CHUNK  1, BLOCK  3 ==

 h:
 f14e85f1 7e3dd3cd 21821aea 13a60dd9 ed703026 6d162747 f486ce97 3b802292

 compress output:
 434b8c2f 418e7faa 7161b184 adc28577 2952f240 a88b1cf8 7bec7d73 c051765d

 == COMPRESS: CHUNK  1, BLOCK  4 ==

 h:
 434b8c2f 418e7faa 7161b184 adc28577 2952f240 a88b1cf8 7bec7d73 c051765d

 compress output:
 421facc4 d3e21e47 c3a23dd3 610bd719 ecdb7a26 8c62e787 fe48f954 938aa686

 == COMPRESS: CHUNK  1, BLOCK  5 ==

 h:
 421facc4 d3e21e47 c3a23dd3 610bd719 ecdb7a26 8c62e787 fe48f954 938aa686

 compress output:
 d6923df3 467f1fd5 0a819a24 abec94ae 9c302aa5 327db5ff 1ba49bc0 165a5863

 == COMPRESS: CHUNK  1, BLOCK  6 ==

 h:
 d6923df3 467f1fd5 0a819a24 abec94ae 9c302aa5 327db5ff 1ba49bc0 165a5863

 compress output:
 f666bec1 6fbbcaea 12a6ebd2 1739df2e 88b9ac50 1ef02104 36bc1314 f7fe8b33

 == COMPRESS: CHUNK  1, BLOCK  7 ==

 h:
 f666bec1 6fbbcaea 12a6ebd2 1739df2e 88b9ac50 1ef02104 36bc1314 f7fe8b33

 compress output:
 967ea734 133aca4b 5f97ef2c cd0077bc acae43c3 2c84abb0 1105580a 494dc582

 == COMPRESS: CHUNK  1, BLOCK  8 ==

 h:
 967ea734 133aca4b 5f97ef2c cd0077bc acae43c3 2c84abb0 1105580a 494dc582

 compress output:
 e1785148 4419c2b9 94dd4c1d 77a352d6 1e2a6e08 316cea7d efe58124 eaa512b0

 == COMPRESS: CHUNK  1, BLOCK  9 ==

 h:
 e1785148 4419c2b9 94dd4c1d 77a352d6 1e2a6e08 316cea7d efe58124 eaa512b0

 compress output:
 fb402a99 554f18e8 ffabb223 42d1c5c1 ff0241f7 13fb6f1b 23af7e2c 2ce45cb7

 == COMPRESS: CHUNK  1, BLOCK 10 ==

 h:
 fb402a99 554f18e8 ffabb223 42d1c5c1 ff0241f7 13fb6f1b 23af7e2c 2ce45cb7

 compress output:
 c5cbd479 30417e86 e1150c46 2d3ea9be c1b8b0d1 c3968e0a a6d74d02 7571b930

 == COMPRESS: CHUNK  1, BLOCK 11 ==

 h:
 c5cbd479 30417e86 e1150c46 2d3ea9be c1b8b0d1 c3968e0a a6d74d02 7571b930

 compress output:
 279a13a8 69c61d6f 0a93894c be859817 9f0790fc 4c096ad4 e4398002 df9b93a5

 == COMPRESS: CHUNK  1, BLOCK 12 ==

 h:
 279a13a8 69c61d6f 0a93894c be859817 9f0790fc 4c096ad4 e4398002 df9b93a5

 compress output:
 a8d114db b86a7942 1e7419c1 6a452196 758a05ca b744e642 93e41248 7cc614e1

 == COMPRESS: CHUNK  1, BLOCK 13 ==

 h:
 a8d114db b86a7942 1e7419c1 6a452196 758a05ca b744e642 93e41248 7cc614e1

 compress output:
 b6e7e6bb 6d3e124f 5dedef9e bde7f593 7a0400d5 50daf53d 49377ad8 dbd6a61f

 == COMPRESS: CHUNK  1, BLOCK 14 ==

 h:
 b6e7e6bb 6d3e124f 5dedef9e bde7f593 7a0400d5 50daf53d 49377ad8 dbd6a61f

 compress output:
 a40be2e1 a5101d8e 902ad7c3 dbac4a0f a1062d4f dbb1d38a 3ef37b7d 0a46f93e

 == COMPRESS: CHUNK  1, BLOCK 15 ==

 h:
 a40be2e1 a5101d8e 902ad7c3 dbac4a0f a1062d4f dbb1d38a 3ef37b7d 0a46f93e

 flags:
 02

 compress output:
 70dc03d8 be50bb38 4a0f7bf3 db9d008b c02b11fb f2ae5f91 4c20d218 5f7db224

 == COMPRESS: PARENT ==

 h:
 6a09e667 bb67ae85 3c6ef372 a54ff53a 510e527f 9b05688c 1f83d9ab 5be0cd19

 m:
 c8d63b32 b1d9fecb dbf2dac7 7fba1e91 a71a614b 022d5eb6 43b88567 5fb98dbb
 70dc03d8 be50bb38 4a0f7bf3 db9d008b c02b11fb f2ae5f91 4c20d218 5f7db224

 t:
 00000000 00000000

 flags:
 0c

 compress output:
 38289de7 d3cc5a91 bab01bb2 f8edb576 d7d308dc 5bb60d8d 370f3f71 46c358ec

 hash value:
 e79d2838915accd3b21bb0ba76b5edf8dc08d3d78d0db65b713f0f37ec58c346
```
