# Prime Order Group (POG) Signatures

[c2sp.org/pogs](https://c2sp.org/pogs)

This document defines the Prime Order Group (POG) signature scheme, a variant of Schnorr signatures
that can utilize any prime-order group and cryptographically-secure hash function that functions as
a random oracle.

## Conventions used in this document

`||` denotes concatenation. `0x` followed by two hexadecimal characters denotes
a byte value in the 0-255 range.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][] [RFC 2119][]
[RFC 8174][] when, and only when, they appear in all capitals, as shown here.


# Cryptographic Dependencies

POG signing depends on the following cryptographic constructs:

- Prime-order Group, {{dep-pog}};
- Cryptographic hash function, {{dep-hash}};

These are described in the following sections.

## Prime-Order Group {#dep-pog}

POG signatures depend on an abelian group of prime order `p`. We represent this
group as the object `G` that additionally defines helper functions described below. The group operation
for `G` is addition `+` with identity element `I`. For any elements `A` and `B` of the group `G`,
`A + B = B + A` is also a member of `G`. Also, for any `A` in `G`, there exists an element
`-A` such that `A + (-A) = (-A) + A = I`. For convenience, we use `-` to denote
subtraction, e.g., `A - B = A + (-B)`. Scalar multiplication is equivalent to the repeated
application of the group operation on an element A with itself `r-1` times, this is denoted
as `r*A = A + ... + A`. For any element `A`, `p * A = I`. We denote `B` as a fixed generator
of the group. Scalar base multiplication is equivalent to the repeated application of the group
operation `B` with itself `r-1` times, this is denoted as `ScalarBaseMult(r)`. The set of
scalars corresponds to `GF(p)`, which we refer to as the scalar field. This document uses types
`Element` and `Scalar` to denote elements of the group `G` and its set of scalars, respectively.
We denote equality comparison as `==` and assignment of values by `=`.

We now detail a number of member functions that can be invoked on `G`.

- Order(): Outputs the order of `G` (i.e. `p`).
- Identity(): Outputs the identity `Element` of the group (i.e. `I`).
- RandomScalar(): Outputs a random `Scalar` element in GF(p).
- SerializeElement(A): Maps an `Element` `A` to a unique byte array `buf` of fixed length `Ne`.
- DeserializeElement(buf): Attempts to map a byte array `buf` to an `Element` `A`,
  and fails if the input is not a valid byte representation of an element of
  the group. This function can raise a DeserializeError if deserialization fails
  or `A` is the identity element of the group; see {{ciphersuites}} for group-specific
  input validation steps.
- SerializeScalar(s): Maps a Scalar `s` to a unique byte array `buf` of fixed length `Ns`.
- DeserializeScalar(buf): Attempts to map a byte array `buf` to a `Scalar` `s`.
  This function can raise a DeserializeError if deserialization fails; see
  {{ciphersuites}} for group-specific input validation steps.

## Cryptographic Hash Function {#dep-hash}

POG signatures require the use of a cryptographically secure hash function, generically written as
H, which functions effectively as a random oracle. For concrete recommendations on hash functions
which SHOULD be used in practice, see {{ciphersuites}}. See {{ciphersuites}} for more details.

[frost]: https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md
