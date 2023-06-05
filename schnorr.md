# Schnorr Signatures

- Version: 0.0.1
- Author: Deirdre Connolly

[c2sp.org/schnorr](https://c2sp.org/schnorr)

## Introduction

This document defines the Schnorr signature scheme, which can utilize any prime-order group and 
cryptographically-secure hash function that functions as a random oracle.

## Conventions used in this document

`||` denotes concatenation. `0x` followed by two hexadecimal characters denotes
a byte value in the 0-255 range.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][] [RFC 2119][]
[RFC 8174][] when, and only when, they appear in all capitals, as shown here.

# Cryptographic Dependencies

Schnorr signing depends on the following cryptographic constructs:

- Prime-order Group, {{dep-pog}};
- Cryptographic hash function, {{dep-hash}};

These are described in the following sections.

## Prime-Order Group {#dep-pog}

Schnorr signatures depend on an abelian group of prime order `p`. We represent this
group as the object `G` that additionally defines helper functions described below. The group operation
for `G` is addition `+` with identity element `I`. For any elements `A` and `B` of the group `G`,
`A + B = B + A` is also a member of `G`. Also, for any `A` in `G`, there exists an element
`-A` such that `A + (-A) = (-A) + A = I`. For convenience, we use `-` to denote
subtraction, e.g., `A - B = A + (-B)`. Integers, taken modulo the group order `p`, are called
scalars; arithmetic operations on scalars are implicitly performed modulo `p`. Since `p` is prime,
scalars form a finite field. Scalar multiplication is equivalent to the repeated
application of the group operation on an element `A` with itself `r-1` times, denoted as
`ScalarMult(A, r)`. We denote the sum, difference, and product of two scalars using the `+`, `-`,
and `*` operators, respectively. (Note that this means `+` may refer to group element addition or
scalar addition, depending on the type of the operands.) For any element `A`, `ScalarMult(A, p) = I`.
We denote `B` as a fixed generator of the group. Scalar base multiplication is equivalent to the repeated application
of the group operation on `B` with itself `r-1` times, this is denoted as `ScalarBaseMult(r)`. The set of
scalars corresponds to `GF(p)`, which we refer to as the scalar field. It is assumed that
group element addition, negation, and equality comparison can be efficiently computed for
arbitrary group elements.

This document uses types `Element` and `Scalar` to denote elements of the group `G` and
its set of scalars, respectively. We denote Scalar(x) as the conversion of integer input `x`
to the corresponding Scalar value with the same numeric value. For example, Scalar(1) yields
a Scalar representing the value 1. Moreover, we use the type `NonZeroScalar` to denote a `Scalar`
value that is not equal to zero, i.e., Scalar(0). We denote equality comparison of these types
as `==` and assignment of values by `=`. When comparing Scalar values, e.g., for the purposes
of sorting lists of Scalar values, the least nonnegative representation mod `p` is used.

We now detail a number of member functions that can be invoked on `G`.

- Order(): Outputs the order of `G` (i.e., `p`).
- Identity(): Outputs the identity `Element` of the group (i.e., `I`).
- RandomScalar(): Outputs a random `Scalar` element in GF(p), i.e., a random scalar in \[0, p - 1\].
- ScalarMult(A, k): Outputs the scalar multiplication between Element `A` and Scalar `k`.
- ScalarBaseMult(k): Outputs the scalar multiplication between Scalar `k` and the group generator `B`.
- SerializeElement(A): Maps an `Element` `A` to a canonical byte array `buf` of fixed length `Ne`. This
  function raises an error if `A` is the identity element of the group.
- DeserializeElement(buf): Attempts to map a byte array `buf` to an `Element` `A`,
  and fails if the input is not the valid canonical byte representation of an element of
  the group. This function raises an error if deserialization fails
  or if `A` is the identity element of the group; see {{ciphersuites}} for group-specific
  input validation steps.
- SerializeScalar(s): Maps a Scalar `s` to a canonical byte array `buf` of fixed length `Ns`.
- DeserializeScalar(buf): Attempts to map a byte array `buf` to a `Scalar` `s`.
  This function raises an error if deserialization fails; see
  {{ciphersuites}} for group-specific input validation steps.

## Cryptographic Hash Function {#dep-hash}

Schnorr sigantures require the use of a cryptographically secure hash function, generically
written as H, which is modeled as a random oracle in security proofs. For concrete 
recommendations on hash functions which SHOULD be used in practice, see {{ciphersuites}}. 
Using H, we introduce distinct domain-separated hashes, H1, H2, H3, H4, and H5:

- H1, H2, and H3 map arbitrary byte strings to Scalar elements associated with the prime-order group.
- H4 and H5 are aliases for H with distinct domain separators.

The details of H1, H2, H3, H4, and H5 vary based on ciphersuite. See {{ciphersuites}}
for more details about each.

# Helper Functions {#helpers}

Beyond the core dependencies, the protocol in this document depends on the
following helper operations:

- Nonce generation {{dep-nonces}}; and
- Encoding operations {{dep-encoding}}.

The following sections describe these operations in more detail.

## Nonce generation {#dep-nonces}

To hedge against a bad RNG that outputs predictable values, nonces are
generated with the `nonce_generate` function by combining fresh randomness
with the secret key as input to a domain-separated hash function built
from the ciphersuite hash function `H`. This domain-separated hash function
is denoted `H3`. This function always samples 32 bytes of fresh randomness
to ensure that the probability of nonce reuse is at most 2<sup>-128</sup>
as long as no more than 2<sup>64</sup> signatures are computed by a given
signing participant.

~~~
Inputs:
- secret, a Scalar.

Outputs:
- nonce, a Scalar.

def nonce_generate(secret):
  random_bytes = random_bytes(32)
  secret_enc = G.SerializeScalar(secret)
  return H3(random_bytes || secret_enc)
~~~

# Schnorr Key Generation {#keygen}

<TODO>

# Schnorr Signature Encoding {#sig-encoding}

This section describes one possible canonical encoding of Schnorr signatures. Using notation
from {{Section 3 of TLS}}, the encoding of a Schnorr signature (R, z) is as follows:

~~~
  struct {
    opaque R_encoded[Ne];
    opaque z_encoded[Ns];
  } Signature;
~~~

Where Signature.R_encoded is `G.SerializeElement(R)` and Signature.z_encoded is
`G.SerializeScalar(z)` and `G` is determined by ciphersuite.

# Schnorr Signature Generation and Verification {#sign-verify}

This section contains descriptions of functions for generating and verifying Schnorr signatures.
The functions for generating and verifying signatures are `sign` and `verify`, respectively.

The function `sign` produces a Schnorr signature over a message given a full secret signing
key as input.

~~~
Inputs:
- msg, message to sign, a byte string.
- sk, secret key, a Scalar.

Outputs:
- (R, z), a Schnorr signature consisting of an Element R and
  Scalar z.

def sign(msg, sk):
  r = G.RandomScalar()
  R = G.ScalarBaseMult(r)
  PK = G.ScalarBaseMult(sk)
  comm_enc = G.SerializeElement(R)
  pk_enc = G.SerializeElement(PK)
  challenge_input = comm_enc || pk_enc || msg
  c = H2(challenge_input)
  z = r + (c * sk) // Scalar addition and multiplication
  return (R, z)
~~~

This section contains a routine for verifying Schnorr signatures with validated inputs.
Specifically, it assumes that signature R component and public key belong to the
prime-order group.

~~~
  verify(msg, sig, PK):

  Inputs:
  - msg, signed message, a byte string
  - sig, a tuple (R, z) output from signature generation
  - PK, public key, an Element

  Outputs: 1 if signature is valid, and 0 otherwise

  def verify(msg, sig = (R, z), PK):
    comm_enc = G.SerializeElement(R)
    pk_enc = G.SerializeElement(PK)
    challenge_input = comm_enc || pk_enc || msg
    c = H2(challenge_input)

    l = G.ScalarBaseMult(z)
    r = R + (c * PK)
    return l == r
~~~

# Ciphersuites {#ciphersuites}

A Schnorr ciphersuite must specify the underlying prime-order group details
and cryptographic hash function. Each ciphersuite is denoted as (Group, Hash),
e.g., (ristretto255, SHA-512). This section contains some ciphersuites.

The DeserializeElement and DeserializeScalar functions instantiated for a
particular prime-order group corresponding to a ciphersuite MUST adhere
to the description in {{dep-schnorr}}. Validation steps for these functions
are described for each the ciphersuites below. Future ciphersuites MUST
describe how input validation is done for DeserializeElement and DeserializeScalar.

## Schnorr(ristretto255, SHA-512) {#recommended-suite}

This ciphersuite uses ristretto255 for the Group and SHA-512 for the Hash function `H`.
The value of the contextString parameter is "SCHNORR-RISTRETTO255-SHA512-v0.0.1".

- Group: ristretto255 {{!RISTRETTO=I-D.irtf-cfrg-ristretto255-decaf448}}
  - Order: 2^252 + 27742317777372353535851937790883648493 (see {{RISTRETTO}})
  - Identity: As defined in {{RISTRETTO}}.
  - RandomScalar: Implemented by repeatedly generating a random 32-byte string and
    invoking DeserializeScalar on the result until success.
  - SerializeElement: Implemented using the 'Encode' function from {{!RISTRETTO}}.
  - DeserializeElement: Implemented using the 'Decode' function from {{!RISTRETTO}}.
  - SerializeScalar: Implemented by outputting the little-endian 32-byte encoding of
    the Scalar value.
  - DeserializeScalar: Implemented by attempting to deserialize a Scalar from a 32-byte
    string. This function can fail if the input does not represent a Scalar between
    the value 0 and `G.Order() - 1`.

- Hash (`H`): SHA-512, and Nh = 64.
  - H2(m): Implemented by computing H(contextString || "chal" || m) and mapping the
    output to a Scalar as described in {{!RISTRETTO, Section 4.4}}.
  - H3(m): Implemented by computing H(contextString || "digest" || m).
  - H4(m): Implemented by computing H(contextString || "nonce" || m) and mapping the
    output to a Scalar as described in {{!RISTRETTO, Section 4.4}}.

## SCHNORR(P-256, SHA-256)

This ciphersuite uses P-256 for the Group and SHA-256 for the Hash function `H`.
The value of the contextString parameter is "SCHNORR-P256-SHA256-v0.0.1".

- Group: P-256 (secp256r1) {{x9.62}}
  - Order: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
  - Identity: As defined in {{x9.62}}.
  - RandomScalar: Implemented by repeatedly generating a random 32-byte string
    and invoking DeserializeScalar on the result until success.
  - SerializeElement: Implemented using the compressed Elliptic-Curve-Point-to-Octet-String
    method according to {{SECG}}.
  - DeserializeElement: Implemented by attempting to deserialize a public key using
    the compressed Octet-String-to-Elliptic-Curve-Point method according to {{SECG}},
    and then performs partial public-key validation as defined in section 5.6.2.3.4 of
    {{!KEYAGREEMENT=DOI.10.6028/NIST.SP.800-56Ar3}}. This includes checking that the
    coordinates of the resulting point are in the correct range, that the point is on
    the curve, and that the point is not the point at infinity. Additionally, this function
    validates that the resulting element is not the group identity element.
    If these checks fail, deserialization returns an error.
  - SerializeScalar: Implemented using the Field-Element-to-Octet-String conversion
    according to {{SECG}}.
  - DeserializeScalar: Implemented by attempting to deserialize a Scalar from a 32-byte
    string using Octet-String-to-Field-Element from {{SECG}}. This function can fail if the
    input does not represent a Scalar between the value 0 and `G.Order() - 1`.

- Hash (`H`): SHA-256, and Nh = 32.
  - H2(m): Implemented using hash_to_field from {{!HASH-TO-CURVE, Section 5.3}}
    using L = 48, `expand_message_xmd` with SHA-256, DST = contextString || "chal", and
    prime modulus equal to `Order()`.
  - H3(m): Implemented by computing H(contextString || "digest" || m).
  - H4(m): Implemented using hash_to_field from {{!HASH-TO-CURVE, Section 5.3}}
    using L = 48, `expand_message_xmd` with SHA-256, DST = contextString || "nonce", and
    prime modulus equal to `Order()`.

## Ciphersuite Requirements {#ciphersuite-reqs}

Future documents that introduce new ciphersuites MUST adhere to
the following requirements.

1. H1, H2, and H3 all have output distributions that are close to
  (indistinguishable from) the uniform distribution.
2. All hash functions MUST be domain separated with a per-suite context
  string.
3. The group MUST be of prime-order, and all deserialization functions MUST
  output elements that belong to their respective sets of Elements or Scalars,
  or failure when deserialization fails.
4. The canonical signature encoding details are clearly specified.

# Security Considerations {#sec-considerations}

~A security analysis of FROST exists in {{FROST20}} and {{StrongerSec22}}. At a high
level, FROST provides security against Existential Unforgeability Under Chosen Message
Attack (EUF-CMA) attacks, as defined in {{StrongerSec22}}. Satisfying this requirement
requires the ciphersuite to adhere to the requirements in {{ciphersuite-reqs}}, as well
as the following assumptions to hold.~

Schnorr signatures do not aim to achieve the following goals:

* Post-quantum security. Schnorr signatures require the hardness of the Discrete Logarithm Problem.
* Downgrade prevention. All participants in the protocol are assumed to agree on what algorithms to use.

The rest of this section documents issues particular to implementations or deployments.

## Side-channel mitigations

Several routines process secret values (nonces, signing keys), and depending
on the implementation and deployment environment, mitigating side-channels may be
pertinent. Mitigating these side-channels requires implementing `G.ScalarMult()`, `G.ScalarBaseMult()`,
`G.SerializeScalar()`, and `G.DeserializeScalar()` in constant (value-independent) time.
The various ciphersuites lend themselves differently to specific implementation techniques
and ease of achieving side-channel resistance, though ultimately avoiding value-dependent
computation or branching is the goal.

## Nonce Reuse Attacks

{{dep-nonces}} describes the procedure that participants use to produce nonces during
the first round of signing. The randomness produced in this procedure MUST be sampled
uniformly at random. The resulting nonces produced via `nonce_generate` are indistinguishable
from values sampled uniformly at random. This requirement is necessary to avoid
replay attacks initiated by other participants, which allow for a complete key-recovery attack.
The Coordinator MAY further hedge against nonce reuse attacks by tracking participant nonce
commitments used for a given group key, at the cost of additional state.

## Input Message Hashing {#pre-hashing}

Schnorr signatures do not pre-hash message inputs. This means that the entire message
must be known in advance of signing. Applications can apply
pre-hashing in settings where storing the full message is prohibitively expensive.
In such cases, pre-hashing MUST use a collision-resistant hash function with a security
level commensurate with the security inherent to the ciphersuite chosen. It is
RECOMMENDED that applications which choose to apply pre-hashing use the hash function
(`H`) associated with the chosen ciphersuite in a manner similar to how `H4` is defined.
In particular, a different prefix SHOULD be used to differentiate this pre-hash from
`H4`. For example, if a fictional protocol Quux decided to pre-hash its input messages,
one possible way to do so is via `H(contextString || "Quux-pre-hash" || m)`.

## Input Message Validation {#message-validation}

Message validation varies by application. For example, some applications may
require that participants only process messages of a certain structure. In digital
currency applications, wherein multiple participants may collectively sign a transaction,
it is reasonable to require that each participant check the input message to be a
syntactically valid transaction.

As another example, some applications may require that participants only process
messages with permitted content according to some policy. In digital currency
applications, this might mean that a transaction being signed is allowed and
intended by the relevant stakeholders. Another instance of this type of message
validation is in the context of {{?TLS=RFC8446}}, wherein implementations may
use threshold signing protocols to produce signatures of transcript hashes. In
this setting, signing participants might require the raw TLS handshake messages
to validate before computing the transcript hash that is signed.

In general, input message validation is an application-specific consideration
that varies based on the use case and threat model. However, it is RECOMMENDED
that applications take additional precautions and validate inputs so that
participants do not operate as signing oracles for arbitrary messages.

# Test Vectors

[frost]: https://github.com/cfrg/draft-irtf-cfrg-frost/blob/master/draft-irtf-cfrg-frost.md
