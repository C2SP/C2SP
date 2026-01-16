# Merkle Tree

This document specifies the Merkle tree structure used by transparency logs. It
defines how to compute tree hashes, and the format and verification of inclusion
and consistency proofs. This structure is compatible with RFC 6962.

## Conventions used in this document

`||` denotes concatenation. `0x` followed by two hexadecimal characters denotes
a byte value in the 0-255 range. `>>` denotes a right bit-shift. `lsb(x)`
denotes the least significant bit of x. `L ++ e` denotes appending element e to
the end of list L.

## Overview

A transparency log Merkle tree is a binary tree built from an ordered list of
entries. The tree structure is uniquely determined by the number of entries
(the tree size). The root hash at any given tree size is a cryptographic
commitment to the ordered list of entries up to that size.

Two key properties of this structure are:

1. **Inclusion proofs**: Given a tree root hash and size, it is possible to
   efficiently prove that a specific entry is at a specific index in the tree.

2. **Consistency proofs**: Given two tree root hashes and sizes, where the
   second size is greater than or equal to the first, it is possible to
   efficiently prove that the first tree is a prefix of the second (i.e., the
   log is append-only).

## Hash function

All hashing operations use SHA-256, producing 32-byte outputs.

Leaf hashes and internal node hashes use different domain separation prefixes.

## Merkle Tree Hash

The Merkle Tree Hash (MTH) is defined recursively over the list of n entries
D[n] = {d[0], d[1], ..., d[n-1]}.

The hash of an empty tree is the SHA-256 hash of the empty string:

    MTH({}) = SHA-256("")

The hash of a tree with a single entry is the SHA-256 hash of a `0x00` byte
followed by the entry:

    MTH({d[0]}) = SHA-256(0x00 || d[0])

For n > 1, let k be the largest power of two smaller than n (i.e., k < n ≤ 2k).
Split the entries into D[0:k] = {d[0], ..., d[k-1]} (the first k entries) and
D[k:n] = {d[k], ..., d[n-1]} (the remaining entries). The hash is:

    MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))

This structure produces a left-balanced binary tree. The left subtree is always
a perfect binary tree (with 2^m leaves for some m), while the right subtree may
not be.

See [Transparent Logs for Skeptical Clients by Russ Cox][] for a more visual explanation.

[Transparent Logs for Skeptical Clients by Russ Cox]: https://research.swtch.com/tlog

## Inclusion proofs

An inclusion proof demonstrates that a specific entry at a given index is
included in a tree of a given size. The proof consists of a list of sibling
hashes along the path from the leaf to the root.

### Proof format

An inclusion proof for the entry at index m in a tree of size n is a list of
hashes. The number of hashes is at most ceil(log2(n)).

The proof is computed using the PATH function, defined recursively:

For a single-entry tree:

    PATH(0, {d[0]}) = {}

For n > 1, let k be the largest power of two smaller than n.

If m < k (the entry is in the left subtree):

    PATH(m, D[n]) = PATH(m, D[0:k]) ++ MTH(D[k:n])

If m >= k (the entry is in the right subtree):

    PATH(m, D[n]) = PATH(m - k, D[k:n]) ++ MTH(D[0:k])

### Verification

To verify an inclusion proof for an entry d at index m in a tree of size n with
root hash r, given the proof hashes {p[0], p[1], ..., p[l-1]}:

1. If m >= n, the proof is invalid.

2. Set fn = m, sn = n - 1, and h = SHA-256(0x00 || d) (the leaf hash).

3. For each proof hash p, in order:
   a. If sn is 0, the proof is invalid (too many proof hashes).
   b. If lsb(fn) is set, or if fn equals sn:
      - Set h = SHA-256(0x01 || p || h).
      - Right-shift both fn and sn until lsb(fn) is set or fn is 0.
   c. Otherwise, set h = SHA-256(0x01 || h || p).
   d. Set fn = fn >> 1 and sn = sn >> 1.

4. If sn is not 0, the proof is invalid (not enough proof hashes).

5. The proof is valid if and only if h equals r.

## Consistency proofs

A consistency proof demonstrates that a tree of size m is a prefix of a tree of
size n (where m <= n). This proves the append-only property: the first m entries
of the larger tree are identical to the entries of the smaller tree.

### Proof format

A consistency proof between trees of size m and n (where m <= n) is a list of
hashes. The number of hashes is at most ceil(log2(n)) + 1.

If m equals n, the trees are identical and no proof is needed (or the proof is
empty and the client just checks that the root hashes match).

If m is 0, the proof is empty (any tree is consistent with an empty tree).

Otherwise, the proof is computed using the SUBPROOF function:

    PROOF(m, D[n]) = SUBPROOF(m, D[n], true)

The SUBPROOF(m, D[n], b) function is defined recursively. The boolean b
indicates whether the subtree root hash should be included in the proof.

If m equals n, the entire subtree is part of the old tree:

    SUBPROOF(m, D[m], true) = {}
    SUBPROOF(m, D[m], false) = {MTH(D[m])}

For m < n, let k be the largest power of two smaller than n:

If m <= k (the old tree ends within the left subtree):

    SUBPROOF(m, D[n], b) = SUBPROOF(m, D[0:k], b) ++ MTH(D[k:n])

If m > k (the old tree extends into the right subtree):

    SUBPROOF(m, D[n], b) = SUBPROOF(m - k, D[k:n], false) ++ MTH(D[0:k])

### Verification

To verify a consistency proof between a tree of size m with root hash r1 and a
tree of size n with root hash r2, given the proof hashes {p[0], p[1], ...,
p[l-1]}:

1. If m > n, the proof is invalid.

2. If m equals n, the proof must be empty and r1 must equal r2.

3. If m equals 0, the proof is valid if and only if it is empty.

4. Otherwise, if the proof is empty, the proof is invalid.

5. If m is a power of 2, prepend r1 to the proof.

6. Set fn = m - 1, sn = n - 1.

7. If lsb(fn) is set, right-shift both fn and sn until lsb(fn) is not set.

8. Set fr = p[0] and sr = p[0].

9. For each remaining proof hash p (starting from p[1]):
   a. If sn is 0, the proof is invalid (too many proof hashes).
   b. If lsb(fn) is set, or if fn equals sn:
      - Set fr = SHA-256(0x01 || p || fr) and sr = SHA-256(0x01 || p || sr).
      - Right-shift both fn and sn until lsb(fn) is set or fn is 0.
   c. Otherwise:
      - Set sr = SHA-256(0x01 || sr || p).
   d. Set fn = fn >> 1 and sn = sn >> 1.

10. If sn is not 0, the proof is invalid (not enough proof hashes).

11. The proof is valid if and only if fr equals r1 and sr equals r2.

## Example

This section illustrates the tree structure using a 7-entry tree with entries
d[0] through d[6]. The leaf hashes and intermediate node hashes are labeled for
reference:

```
             root
            /    \
           /      \
          k        l
         / \      / \
        /   \    /   \
       h     i  j     |
      / \   / \ |\    |
     a   b c  d e f   g
     |   | |  | | |   |
  d[0] d[1] .... d[5] d[6]
```

Where the leaf hashes are:

    a = SHA-256(0x00 || d[0])
    b = SHA-256(0x00 || d[1])
    c = SHA-256(0x00 || d[2])
    d = SHA-256(0x00 || d[3])
    e = SHA-256(0x00 || d[4])
    f = SHA-256(0x00 || d[5])
    g = SHA-256(0x00 || d[6])

And the internal nodes are:

    h = SHA-256(0x01 || a || b)
    i = SHA-256(0x01 || c || d)
    j = SHA-256(0x01 || e || f)
    k = SHA-256(0x01 || h || i)
    l = SHA-256(0x01 || j || g)
    root = SHA-256(0x01 || k || l)

### Inclusion proofs

Using the labels above, the inclusion proofs for the 7-entry tree are:

- d[0] at index 0: [b, i, l]
- d[3] at index 3: [c, h, l]
- d[4] at index 4: [f, g, k]
- d[6] at index 6: [j, k]

### Consistency proofs

Using the labels above:

- From size 3 to size 7: [c, d, h, l]
- From size 4 to size 7: [l]
- From size 6 to size 7: [j, g, k]

## References

This specification is derived from [RFC 6962][], Section 2.1, with verification
algorithms based on [RFC 9162][], Section 2.1.

[RFC 6962]: https://www.rfc-editor.org/rfc/rfc6962.html
[RFC 9162]: https://www.rfc-editor.org/rfc/rfc9162.html
