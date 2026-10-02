---
description: Post-quantum key encapsulation mechanism
---

> [!WARNING]
> This is the editor's copy of this specification.
> For a stable rendered reference, use [c2sp.org/kopis](https://c2sp.org/kopis).

# The Kopis Key Encapsulation Mechanism

This document contains a specification for the [Kopis](https://eprint.iacr.org/2026/2268) post-quantum key encapsulation mechanism (KEM). We do this in two parts, first defining an IND-CPA-secure public key encryption (PKE) scheme, then defining the IND-CCA-secure KEM via the Fujisaki-Okamoto transform.

# Preliminaries

We first specify all the algorithms, syntax, and mathematics we will need for the specification.

## Dependencies

We use the TurboSHAKE XOF family defined in [RFC 9861](https://www.rfc-editor.org/rfc/rfc9861.html). We invoke it as `TurboSHAKE128/TurboSHAKE256(M, L, D)`, where `M` is the message to be hashed, `L` is the desired output length, and `D` is the domain separator in the range `[0x01, 0x7f]`.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [BCP 14](https://www.rfc-editor.org/info/bcp14) [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.html) [RFC 8174](https://www.rfc-editor.org/rfc/rfc8174.html) when, and only when, they appear in all capitals, as shown here.

## Syntax

We use pseudocode resembling a mix of Rust and Python. Variables declared with `let mut` are mutable. Function definitions are preceded with `fn`, each function input name is followed by a colon, then the type signature, and each function is followed by an arrow `->` then the return type. Ranges are denoted `a..b`, and indicate the range `[a, b)` (i.e., including `a`, excluding `b`). When `s` is a sequence type (e.g., a bitstring or bytestring), `s[a..b]` is used to denote the subsequence starting at index `a` (0-indexed), and ending at and excluding index `b`. We use underscores in the LHS of assignments to denote the elision of a value that is normally bound, e.g., `let (a, _) = f()` where `f()` returns two values. We use ellipses to denote the elision of multiple values, e.g., `let (a, ...) = f()`, where `f()` returns three values. We use infix `||` to denote concatenation of bytestrings. We use infix `^` to denote integer exponentiation when the inputs are expressions. We write `[uK; N]` to mean an array of `N` many `K`-bit integers. Subtraction over `uK` is always defined as wrapping subtraction, e.g., `0u8 - 1u8 = 255u8`.

## Mathematical Definitions

Let `R` be the negacyclic polynomial ring `ℤ[X]/(X²⁵⁶ + 1)`. We denote by `R13` the polynomial ring modulo `2^13`, i.e., `R/2¹³R` (this is isomorphic to `(ℤ/2¹³ℤ)[X]/(X²⁵⁶ + 1)`). Similarly, `R10` denotes `R/2¹⁰R` and `R1` denotes `R/2R`.

The type `MatRn` refers to `Rn^(ℓ×ℓ)`, i.e., `ℓ×ℓ` matrices of elements of `Rn`, for any `n`. Similarly, the type `VecRn` refers to `Rn^ℓ`, i.e., vectors of `ℓ` elements of `Rn`. For any `n`, we write `make_rn` to refer to the natural morphism from the space of coefficients `[un; 256]` to `Rn` (input is interpreted lowest-degree-coefficient-first). `make_matn` takes a nested array `[[Rn; ℓ]; ℓ]` and interprets it as a list of rows in a matrix in `MatRn`. `make_vecn` takes an array `[Rn; ℓ]` and interprets it as a column vector in `VecRn`, in the same order as `make_matn`, i.e., such that `make_matn([eye, zeros, ... zeros]) * make_vecn(eye) = make_vecn(eye)`, where `eye = [1, 0, ..., 0]` , and `zeros = [0, 0, ..., 0]` (interpreting the numbers as ring elements). When indexing into a vector `v: VecRn` for some `n`, we do so in the same order that was used in its constructor, i.e., `v[i]` equals `a[i]` where `a` is the input to the `make_vecn` that constructed `v`. `transpose` transposes the given matrix or vector. 

When we write `r as U` for some type `U`, we mean to invoke either the natural injection or projection of `r` into/onto `U`. For example, if `r` is in `VecR10` and `U` is `VecR13`, then it is the natural injection, and if vice-versa, then it is the natural projection by quotienting by `2¹⁰R13`.

For any modulus `N`, we say the canonical form of an element of `ℤ/Nℤ` is its representative integer in `[0, N)`. For any `n` and a ring element `r` we say its _canonical coefficients_ `canonical_coeffs(r: Rn) -> [un; 256]` are the unique sequence of 256 `un` values `a_0, ..., a_255` such that `r = a_255 X^255 + ... + a_1 X + a_0`.

For an element `r` in `Rn` and integer `N`, we define the right-shift `r >> N` as `make_rn([a_0 >> N, a_1 >> N, ..., a_255 >> N])` where `a_i` are the canonical coefficients of `r`. We define left-shift `r << N` similarly, with coefficients reduced mod `2^n`. We define right and left shift for elements of `VecRn` as operating element-wise.

We define `to_bits_le(n: ℤ, k: un) -> [bool; n]` to be the function that converts an `n`-bit integer to its bit representation, starting with the least significant bit. Similarly, we define `from_bits_le(n: ℤ, bits: [bool; n]) -> un` to interpret `n` bits as a `un` value, using `bits[0]` as the least significant bit of the output, and so on.

# Main Algorithms

We now define a **public key encryption (PKE) scheme**. For the purposes of this specification, the secret key space is simply `[u8; 32]`, and generating a fresh secret key amounts to generating a fresh uniform bytestring. We define a public key encryption scheme as the set of the following algorithms:

* `SkToPk(sk) -> pk` — Computes the public key corresponding to the given secret key
* `PkeEncrypt(randomness, pk, msg) -> ct` — Encrypts the given message `msg` to public key `pk`, using encryption randomness `randomness`
* `PkeDecrypt(sk, ct) -> msg` — Decrypts the given ciphertext `ct` using the secret key `sk`, and unconditionally returns a message `msg`

We now define a **key encapsulation mechanism (KEM)**. Similar to the PKE above, secret keys are uniform elements of `[u8; 32]`. A KEM is defined as the set of the following algorithms:

* `SkToPk(sk) -> pk` — Computes the public key corresponding to the given secret key
* `KemEncap(randomness, pk) -> (k, ct)` — Encapsulates a shared secret `k` to public key `pk`, using randomness `randomness`. Outputs a `k` and a ciphertext `ct`.
* `KemDecap(sk, ct) -> k` — Decrypts the ciphertext `ct` using the secret key `sk`, and unconditionally returns a shared secret `k`

For real-world usage of these algorithms, the `randomness` parameters above MUST be sampled uniformly.

An implementation note: the purpose of Kopis is to be used in settings that require constant-time operations. Thus, any implementation of the above functions MUST be constant-time with respect to all inputs.

## Parameters

The following variables represent security parameters, and depend on the security level being instantiated:

* `ℓ` — The public matrix dimension. This impacts the size of public keys and ciphertexts
* `μ` — The binomial parameter used for secret generation. This is always even.
* `t` — The base-2 logarithm of the modulus of the space of compressed ring elements

## Constants

We define the constants used in our implementation. The sizes in bytes of our secret keys, public keys, and ciphertexts are functions of the parameters above:

* `SK_SIZE = 32`
* `PK_SIZE = 256*ℓ*10/8 + 32`
* `CT_SIZE = 256*t/8 + 256*ℓ*10/8`

We also require domain separators for all our TurboSHAKE invocations:

* `DOMSEP_KGEXPAND = 0x01`
* `DOMSEP_GENMAT = 0x02`
* `DOMSEP_GENSEC = 0x03`
* `DOMSEP_PKHASH = 0x04`
* `DOMSEP_FO = 0x05`
* `DOMSEP_NOREJECT = 0x06`

## PKE

We define key generation, encryption, and decryption for the Kopis IND-CPA-secure PKE scheme. We will define the helper functions later.

```
fn SkToPk(sk: [u8; 32]) -> [u8; PK_SIZE]:
  let (_, _, pk, _) = ExpandSecretKey(sk)
  return pk

fn PkeEncrypt(
  randomness: [u8; 32],
  pk: [u8; PK_SIZE],
  msg: [u8; 32]
) -> [u8; CT_SIZE]:
  let vec_b = deserialize_vec(10, pk[..256*ℓ*10/8])
  let mat_seed = pk[256*ℓ*10/8..]
  let m = deserialize_elem(1, msg)

  let mat_A = GenMat(mat_seed)
  let vec_sprime = GenSecret(randomness)
  let vec_bprime = CompressToR10(mat_A * vec_sprime)
  let vprime = transpose(vec_b) * (vec_sprime as VecR10)
  let cm = CompressToRt(vprime - ((m as R10) << 9))

  let ct = serialize_vec(10, vec_bprime) || serialize_elem(t, cm)
  return ct

fn PkeDecrypt(sk: [u8; 32], ct: [u8; CT_SIZE]) -> [u8; 32]:
  let (vec_s, ...) = ExpandSecretKey(sk)
  let vec_bprime = deserialize_vec(10, ct[..256*ℓ*10/8])
  let cm = deserialize_elem(t, ct[256*ℓ*10/8..])
  let v = transpose(vec_bprime) * (vec_s as VecR10)
  let cm10 = (cm as R10) << (10 - t)
  let mprime = DecodeMsg(v - cm10)
  return serialize_elem(1, mprime)
```

## KEM

We define the IND-CCA-secure Kopis KEM below. The `SkToPk` function is identical to the one given in the PKE above.

```
fn KemEncap(
  randomness: [u8; 32],
  pk: [u8; PK_SIZE]
) -> ([u8; 32], [u8; CT_SIZE]):
  # Derive the output key and encryption randomness
  let pkh = TurboSHAKE256(pk, 32, DOMSEP_PKHASH)
  let b = TurboSHAKE256(randomness || pkh, 64, DOMSEP_FO)
  let (k, r) = (b[..32], b[32..])

  # Encrypt to pk. `randomness` is itself the message
  let ct = PkeEncrypt(r, pk, randomness)

  return (k, ct)

fn KemDecap(sk: [u8; 32], ct: [u8; CT_SIZE]) -> [u8; 32]:
  let (_, z, pk, pkh) = ExpandSecretKey(sk)

  let randomness = PkeDecrypt(sk, ct)
  let b = TurboSHAKE256(randomness || pkh, 64, DOMSEP_FO)
  let (k, rprime) = (b[..32], b[32..])
  let cprime = PkeEncrypt(rprime, pk, randomness)

  if ct == cprime:
    return k
  else:
    return TurboSHAKE256(z || ct, 32, DOMSEP_NOREJECT)
```

We note again that, along with all other top-level functions, `KemDecap` MUST be constant time with respect to its inputs. In particular, an implementer MUST perform the ciphertext equality check in constant time.

For efficiency, implementers MAY internally cache the expanded decapsulation key. But this expanded key SHOULD NOT be persisted anywhere.

## Auxiliary Functions

We now define the auxiliary functions used in the schemes above:

```
fn ExpandSecretKey(
  sk: [u8; 32]
) -> (VecR13, [u8; 32], [u8; PK_SIZE], [u8; 32]):
  let randomness = TurboSHAKE256(sk || (ℓ as u8), 96, DOMSEP_KGEXPAND)
  let mat_seed = randomness[..32]
  let secret_seed = randomness[32..64]
  let z = randomness[64..]

  let mat_A = GenMat(mat_seed)
  let vec_s = GenSecret(secret_seed)
  let vec_b = CompressToR10(transpose(mat_A) * vec_s)
  let pk = serialize_vec(10, vec_b) || mat_seed
  let pkh = TurboSHAKE256(pk, 32, DOMSEP_PKHASH)

  return (vec_s, z, pk, pkh)

fn CompressToR10(v: VecR13) -> VecR10:
  let h1 = make_r13([4u13; 256])
  let h = make_vec13([h1; ℓ])
  let s = (v + h) >> 3
  return (s as VecR10)

fn CompressToRt(r: R10) -> Rt:
  let h1 = make_r10([4u10; 256])
  let s = (r + h1) >> (10 - t)
  return (s as Rt)

fn DecodeMsg(r: R10) -> R1:
  let h2 = make_r10([2^8 - 2^(10-t-1) + 4; 256])
  let s = (r + h2) >> 9
  return (s as R1)

fn GenMat(seed: [u8; 32]) -> MatR13:
  let A: [[R13; ℓ]; ℓ]
  for i in 0u8..ℓ:
    for j in 0u8..ℓ:
      let buf = TurboSHAKE128(seed || i || j, 256*13/8, DOMSEP_GENMAT)
      A[i][j] = deserialize_elem(13, buf)
  return make_mat13(A)

fn GenSecret(seed: [u8; 32]) -> VecR13:
  let s: [R13; ℓ]
  for i in 0u8..ℓ:
    let buf = TurboSHAKE256(seed || i, μ*256/8, DOMSEP_GENSEC)
    let vals = bit_slices(buf)
    let r: [u13; 256]
    for k in 0..256:
      # Recall subtraction is wrapping
      r[k] = hamming(vals[2*k]) - hamming(vals[2*k+1])
    s[i] = make_r13(r)
  return make_vec13(s)

# Serializes an element of Rn (for any choice n=13,10,1,t)
fn serialize_elem(n: ℤ, r: Rn) -> [u8; n*256/8]:
  let a = canonical_coeffs(r)

  let all_bits: [bool; n*256]
  for i in 0..256:
    all_bits[n*i..n*(i+1)] = to_bits_le(n, a[i])

  let out: [u8; 32*n]
  for i in 0..32*n:
    out[i] = from_bits_le(8, all_bits[8*i..8*(i+1)])
  return out

# Serializes an element of VecRn (for any choice n=13,10,1,t)
fn serialize_vec(n: ℤ, v: VecRn) -> [u8; ℓ*n*256/8]:
  let out: [u8; ℓ*n*32]
  for i in 0..ℓ:
    out[n*32*i..n*32*(i+1)] = serialize_elem(n, v[i])
  return out

# Deserializes an element of Rn (for any choice n=13,10,1,t)
fn deserialize_elem(n: ℤ, bytes: [u8; n*256/8]) -> Rn:
  let all_bits: [bool; n*256]
  for i in 0..n*32:
    all_bits[8*i..8*(i+1)] = to_bits_le(8, bytes[i])

  let coeffs: [un; 256]
  for i in 0..256:
    coeffs[i] = from_bits_le(n, all_bits[n*i..n*(i+1)])
  return make_rn(coeffs)

# Deserializes an element of VecRn (for any choice n=13,10,1,t)
fn deserialize_vec(n: ℤ, bytes: [u8; ℓ*n*256/8]) -> VecRn:
  let elems: [Rn; ℓ]
  for i in 0..ℓ:
    elems[i] = deserialize_elem(n, bytes[n*32*i..n*32*(i+1)])
  return make_vecn(elems)

# Reinterprets a bytestring as a sequence of bitstrings of length μ/2
fn bit_slices(bytes: [u8; μ*256/8]) -> [[bool; μ/2]; 512]:
  let all_bits: [bool; μ*256]
  for i in 0..μ*32:
    all_bits[8*i..8*(i+1)] = to_bits_le(8, bytes[i])

  let out: [[bool; μ/2]; 512]
  for i in 0..512:
    out[i] = all_bits[i*μ/2..(i+1)*μ/2]
  return out

# Returns the number of set bits in b
fn hamming(b: [bool; μ/2]) -> u13:
  let mut weight = 0u13
  for i in 0..μ/2:
    if b[i]:
      weight += 1
  return weight
```

# Parameter Sets

We define three security levels for Kopis: Kopis-512, Kopis-768, and Kopis-1024, referring to the dimension of the public key vector over `ℤ/2¹⁰ℤ`:

|Name       | Parameters     | `PK_SIZE` | `CT_SIZE` | `SK_SIZE` |
|---------- |----------------|-----------|-----------|-----------|
|Kopis-512  | `ℓ=2 t=3 μ=10` | 672       | 736       | 32        |
|Kopis-768  | `ℓ=3 t=4 μ=8`  | 992       | 1088      | 32        |
|Kopis-1024 | `ℓ=4 t=6 μ=6`  | 1312      | 1472      | 32        |

# Test Vectors

Test vectors and a Python reference implementation can be found at [CCTV](https://github.com/C2SP/CCTV/tree/main/kopis).
