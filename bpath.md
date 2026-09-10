# Batched Merkle Inclusion Proofs

This document defines the `BPATH` algorithm for proving inclusion of multiple leaves in a Merkle tree. This standard extends the `PATH` function defined in the Certificate Transparency standard, [RFC 6962][]. `BPATH` is equivalent to `PATH` whenever just one leaf's membership is being proved.

## Conventions used in this document

We use the same notation as in [RFC 6962][]. `D[n]` denotes a list of `n` elements: `{d(0), d(1), ..., d(n-1)}`. `D[k1:k2]` denotes the length `(k2 - k1)` list `{d(k1), d(k1+1), ..., d(k2-1)}`. `D : E` denotes the concatenation of lists `D` and `E`. When `c` is an integer and `M[r]` is a list of integers, `M[k1:k2] - c` denotes the list `{m(k1) - c, m(k1+1) - c, ..., d(k2-1) - c}`. `MTH(D[n])` denotes the Merkle Tree Hash of `D[n]`, i.e., the root of the complete Merkle Tree whose leaves are the elements of `D[n]`. Finally, `I2OSP(n, w)` denotes the function that returns the width-`w` big-endian encoding of the non-negative integer `n`, as described in [RFC 8017][].

As in [RFC 6962][], the algorithm defined in this document is generic over the choice of hash function, and we do not fix a canonical hash function. We provide test vectors over the `SHA-256` [FIPS 180-4][], `BLAKE2s` [RFC 7693][], and `SHAKE256` [FIPS 202][] hash functions. Python 3 code is provided for end users who wish to generate test vectors using other hash functions.

## Batch Merkle Audit Paths

We extend the `PATH` function defined in [RFC 6962, section 2.1.1][PATH def]. Given a list of leaves `D[n]` and an index `m` with `0 <= m < n`, `PATH` produces a proof that `d(m)` appears in `D[n]`. A verifier of a `PATH` proof need only know `d(m)` and `MTH(D[n])` in order to verify the proof. `BPATH` is the batched version of `PATH`: it constructs a proof that multiple leaves, whose indices are given by a (sorted) list `M[r]`, appear in `D[n]`. A verifier of `BPATH` proof need only know `{d(m(0)), ..., d(m(r-1))}` and `MTH(D[n])` in order to verify the proof.

The purpose of `BPATH` is to produce much smaller proofs of multiple inclusion. Semantically, a `BPATH` proof over `M[r]` is equivalent to `r` `PATH` proofs, one for each individual index. However, the `r` `PATH` proofs may contain large amounts of redundant information. For example, using a hash function with 256-bit digests, the full set of `PATH` proofs for the first 100 leaves in a 1000-leaf tree is 32KB, whereas the `BPATH` proof for the same set is 192B (0.6%). A `BPATH` proof is smaller than the corresponding set of `PATH` proofs whenever `r > 1`.

Finally, as stated above, `BPATH` is backwards compatible with `PATH`. Concretely, `BPATH({m}, D[n]) == PATH(m, D[n])` for all lists `D[n]` and integers `m` where `0 < m <= n`.

### Definition
 
Given a list of `n` leaves, `D[n] = {d(0), ..., d(n-1)}`, and a list of `r` indices `M[r] = {m(0), ..., m(r-1)}` with `0 <= m(0) < ... m(r-1) < n`, the batched Merkle audit path `BPATH(M[r], D[n])` is defined as follows.

The batched proof for the single leaf in a tree with a one-element input list `D[1] = {d(0)}` is empty:

```
BPATH({0}, {d(0)}) = {}
```

For `n > 1`, let `k` be the largest power of two smaller than `n`. Let `l` be the largest integer such that `m(i) < k` for all `i < l`, i.e., all of `M[0:l]` is in the left subtree of `D[n]`, and all of `M[l:r]` is in the right subtree of `D[n]`.

In the case `l == r`, no index `m(i)` is in the right subtree, so the batch proof must provide the right subtree hash. Similarly, in the case `l == 0`, no `m(i)` is in the left subtree, so the batch proof must provide the left subtree hash. In all other cases, both subtrees must be recursed upon. Concretely, the batched path is defined in the recursive as:

```
if l == r:
    BPATH(M[r], D[n]) = BPATH(M[r], D[0:k]) : MTH(D[k:n])
else if l == 0:
    BPATH(M[r], D[n]) = BPATH(M[r] - k, D[k:n]) : MTH(D[0:k])
else:
    BPATH(M[r], D[n]) =
        BPATH(M[0:l], D[0:k]) : BPATH(M[l:r] - k, D[k:n])
```

## Test Vectors

We provide test vectors in **[TODO: pick a place to put these]**, not just for `BPATH`, but also for the Merkle tree functions defined in [RFC 6962][]. Python 3 test vector generation code can be found at **[TODO: pick a place for this too]**.

In each test vector, the `num_leaves` key indicates the number of leaves in the tree `D[num_leaves]`. Each leaf `d(i)` is defined to be `I2OSP(i, 2)`, i.e., the 2 byte big-endian representation of the integer `i`. The structure of the test vectors is as follows:

**TODO: Update structures once KATs for other hash functions are written**

### Merkle Tree Hash (`mth.json`)

* `num_leaves` - The number of leaves in the tree
* `tree_hash` - The value of `MTH(D[num_leaves])`, encoded in hex

### Merkle Audit Path (`path.json`)

* `num_leaves` - The number of leaves in the tree
* `idx` - The index of the leaf whose membership is being proved
* `inclusion_proof` - The value of `PATH(idx, D[num_leaves])`, encoded in hex

### Batch Merkle Audit Path (`bpath.json`)

* `num_leaves` - The number of leaves in the tree
* `idxs` - The indices of the leaves whose memberships are being batch-proved
* `batch_inclusion_proof` - The value of `BPATH(idxs, D[num_leaves])`, encoded in hex

### Consistency Proof (`consistency.json`)

* `num_leaves` - The number of leaves in the tree
* `subtree_size` - The size of the left subtree which we want to show is consistent with `D[num_leaves]`
* `consistency_proof` - The value of `PROOF(subtree_size, D[num_leaves])`, encoded in hex

[RFC 6962]: https://www.rfc-editor.org/info/rfc6962
[RFC 7693]: https://www.rfc-editor.org/info/rfc7693
[RFC 8017]: https://www.rfc-editor.org/info/rfc8017
[PATH def]: https://datatracker.ietf.org/doc/html/rfc6962#section-2.1.1
[FIPS 180-4]: http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf
[FIPS 202]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
