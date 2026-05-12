# COCKTAIL Distributed Key Generation

[c2sp.org/cocktail-dkg](https://c2sp.org/cocktail-dkg)

- **Version**: v0.2.0
- **Authors**:
  - [Daniel Bourdrez](https://github.com/bytemare)
  - [Soatok Dreamseeker](https://github.com/soatok)
  - [Tjaden Hess](https://github.com/tjade273), *[Trail of Bits](https://trailofbits.com)*
  - COCKTAIL is an independent derivative of [ChillDKG](https://github.com/BlockstreamResearch/bip-frost-dkg/tree/master),
    which was made by:
    - [Tim Ruffing](https://github.com/real-or-random), *Blockstream Research*
    - [Jonas Nick](https://github.com/jonasnick), *Blockstream Research*

## Introduction

Threshold signature schemes (i.e., [FROST (RFC 9591)](https://www.rfc-editor.org/rfc/rfc9591.html)) allow a secret key
be shared among $n$ parties such that any $t$ of the $n$ parties can cooperate to generate a digital signature for the
group public key.

Initializing a $t$-of-$n$ threshold requires a key generation protocol. This can be a **Distributed Key Generation**
(DKG) protocol or a Trusted Dealer approach. RFC 9591 specifies a Trusted Dealer approach and leaves DKG specification
out of scope.

However, [the original FROST paper](https://eprint.iacr.org/2020/852) did specify a DKG protocol based on Verifiable
Secret Sharing, Pedersen commitments, and Proofs of Possession. This protocol is secure only if communications are
performed over a secure channel, with the following requirements:

- Messages are authenticated and encrypted in transit, to prevent man-in-the-middle attacks
- All participants have some consensus mechanism (e.g., a transparency log) so everyone has a consistent view of the
  protocol messages

To satisfy these requirements in a standalone protocol, Nick and Ruffing proposed [ChillDKG](https://github.com/BlockstreamResearch/bip-frost-dkg)
as a Bitcoin Improvement Proposal. Because of its tight coupling to the Bitcoin project, ChillDKG was only specified and
implemented over the secp256k1 elliptic curve group.

> COCKTAIL is a recursive acronym that stands for: "COCKTAIL Orchestrates Cryptographic Key Threshold Agreement for
> Interoperable Libraries."

COCKTAIL is an independent derivative of ChillDKG intended to be used with any FROST ciphersuite.

## Abstract

COCKTAIL-DKG is a standalone, three-round distributed key generation protocol for threshold signature schemes like 
FROST.

COCKTAIL-DKG allows a group of $n$ participants to securely generate a shared group public key and individual secret
shares for a $t$-of-$n$ threshold, without a trusted dealer. The protocol is built on Feldman's Verifiable Secret
Sharing (VSS), uses pairwise ECDH to encrypt shares for transport over insecure channels, and includes a final
certification round to ensure all participants agree on the outcome. It is designed to be ciphersuite-agile, with
specific recommendations for curves like secp256k1, Ed25519 (via Ristretto255), and Ed448.

## Design Overview

COCKTAIL-DKG, like ChillDKG before it, starts off with a simplified variant of a Pedersen Commitment with Proof of
Possession protocol, referred to as "SimplPedPop". If SimplPedPop were a standalone protocol, it would depend on an
external *equality check protocol* to ensure all participants received the same messages.

An encryption layer, called "EncPedPop", wraps SimplPedPop with pairwise ECDH to encrypt secret shares.

Finally, an equality check protocol called "CertEq" is built atop EncPedPop to create a standalone protocol.

A **coordinator** is assumed to facilitate message passing between participants. The coordinator is an **untrusted
facilitator**: it is responsible for receiving messages from all participants, aggregating them where necessary, and
broadcasting them to all participants, but it is **not trusted** with the confidentiality, integrity, or consistency
of any protocol message. A malicious coordinator can disrupt **availability** (a liveness concern: refusing to
broadcast, dropping participants, or stalling the protocol; none of which can be prevented by cryptographic
mechanisms), but it cannot break **confidentiality** (it never sees any participant's secret share or the final 
group secret key) or **consistency** (any split-view attack, in which different participants receive different
messages, causes the CertEq phase to fail safely with all-or-nothing semantics). The coordinator does not need any
private key material. The role of the coordinator can be fulfilled by a simple broadcast channel, a peer-to-peer
network among the participants themselves, or a dedicated server application; the choice does not change the
protocol's security properties.

## Supporting Definitions

This section provides detailed definitions for the notation, message formats, and cryptographic primitives used
throughout the COCKTAIL-DKG protocol.

### Notation

- $X \parallel Y$: The concatenation of X followed by Y.
- $n$: The total number of participants in the DKG ceremony.
- $t$: The threshold, i.e., the minimum number of participants required to generate a signature.
- $i, j$: Indices representing participants, where $1 <= i, j <= n$.
- $B$: The generator point of the elliptic curve group.
- $q$: The order of the elliptic curve group.
- $f_i(x)$: The secret polynomial of degree $t-1$ generated by participant $i$.
- $a_{i,k}$: The $k$-th coefficient of $f_i(x)$, which is a scalar. $a_{i,0}$ is the primary secret of participant $i$.
- $C_{i,k}$: The public commitment to the coefficient $a_{i,k}$, where $C_{i,k} = a_{i,k} * B$.
- $C_i$: The VSS commitment for participant $i$, which is the vector of all $C_{i,k}$.
- $s_{i,j}$: The secret share of participant $i$'s polynomial evaluated at $j$, i.e., $s_{i,j} = f_i(j)$.
- $d_i$: The long-term static private key for participant $i$, a scalar.
- $P_i$: The long-term static public key for participant $i$, where $P_i = d_i * B$.
- $e_i$: The ephemeral private key for participant $i$ for a single DKG session, a scalar.
- $E_i$: The ephemeral public key for participant $i$, where $E_i = e_i * B$.
- $PoP_i$: A Proof of Possession signature from participant $i$.
- $x_i$: The final, long-lived secret share for participant $i$, where $x_i = \sum_{j=1}^{n} s_{j,i}$.
- $Y_i$: The public verification share for participant $i$.
- $Y$: The final group public key, where $Y = \sum_{j=1}^{n} C_{j,0}$.
- $payload_{i,j}$: An optional application-defined payload from participant $i$ to participant $j$, which may be empty.
- $S^{(e)}_{i,j}$: The ephemeral-to-static ECDH shared secret, where $S^{(e)}_{i,j} = e_i * P_j$. When $S^{(e)}_{i,j}$
  appears as bytes (e.g., inside $x = S^{(e)} \parallel S^{(d)}$ as an input to $H6$), it is the canonical
  ciphersuite-specific byte encoding of the elliptic-curve point $e_i \cdot P_j$ as defined in
  [ECDH Shared-Secret Encoding](#ecdh-shared-secret-encoding).
- $S^{(d)}_{i,j}$: The static-to-static ECDH shared secret, where $S^{(d)}_{i,j} = d_i * P_j$. Encoded as bytes per
  [ECDH Shared-Secret Encoding](#ecdh-shared-secret-encoding).

### Operations

- $Add(P_1, P_2)$: Elliptic curve point addition.
- $RandomScalar()$: Generates a uniform cryptographically secure random scalar in the range $[0, q-1]$.
- $H6()$: A ciphersuite-specific key derivation function.
- $H7()$ and $HashToScalar()$: Ciphersuite-specific tagged hash and hash-to-scalar functions, defined in
  [Schnorr Signature Scheme](#schnorr-signature-scheme).
- $Enc()$/$Dec()$: Ciphersuite-specific AEAD encryption/decryption functions.
- $Sign()$/$Verify()$: The Schnorr signature scheme defined in
  [Schnorr Signature Scheme](#schnorr-signature-scheme), used for both the Proof of Possession and CertEq
  transcript certification.
- $ecdh\_encode(P)$: A ciphersuite-specific canonical byte encoding of an elliptic-curve point $P$, used to
  serialize ECDH shared-secret outputs before they are fed into $H6$. The encoding is fixed-length per
  ciphersuite and is defined in [ECDH Shared-Secret Encoding](#ecdh-shared-secret-encoding). Any reference to
  the bytes of an ECDH product (e.g., $S^{(e)}_{i,j} = e_i \cdot P_j$ used as an input to $H6$) means
  $ecdh\_encode$ applied to that product.
- $uint64\_be(v)$ and $uint64\_be\_decode(b)$: The 8-byte big-endian encoding and decoding of a 64-bit unsigned
  integer, used for the variable-length-ciphertext length prefixes in $msg_{1|i}$, $msg_{2|i}$, and $C^{rec}_i$.

### Message Formats

All messages exchanged between participants are encoded as byte arrays. The specific encoding of protocol elements is
defined below. Implementations **MUST** adhere to these formats to ensure interoperability.

#### Primitive Types

Let $G$ be an elliptic curve group with a standardized name (e.g., "P-256", "Ed25519", "secp256k1").

- **Scalar**: A scalar is an integer in the range $[0, q-1]$, where $q$ is the order of the group $G$. A scalar is
  encoded as a fixed-size byte array using the encoding defined by the corresponding FROST ciphersuite in
  [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html#name-ciphersuites) (or, for ZIP-0312 ciphersuites, the
  encoding defined in [ZIP-0312](https://zips.z.cash/zip-0312#ciphersuites)). The endianness is therefore
  ciphersuite-specific:
  - Ed25519, Ristretto255, Ed448, JubJub, Pallas: **little-endian**.
  - P-256, secp256k1: **big-endian**.

  Scalar sizes are: 32 bytes for P-256, secp256k1, Ed25519/Ristretto255, JubJub, and Pallas; and 57 bytes for
  Ed448, matching RFC 9591.
  Implementations **MUST** reject any decoded scalar value $s$ where $s \geq q$. When a scalar value is the result
  of arithmetic operations (e.g., polynomial evaluation $f_i(j)$, share summation $x_i = \sum_j s_{j,i}$, or
  index powers $i^k$), implementations **MUST** reduce the result modulo $q$ before encoding it to bytes;
  implementations using arbitrary-precision integer types are particularly susceptible to silently encoding an
  unreduced value that is larger than $q$.
- **Elliptic Curve Point**: An elliptic curve point is encoded in its compressed form, as a fixed-size byte array,
  using the corresponding FROST ciphersuite encoding from RFC 9591 / ZIP-0312. Sizes are: 33 bytes for P-256 and
  secp256k1; 32 bytes for Ed25519/Ristretto255, JubJub, and Pallas; and 57 bytes for Ed448, matching RFC 9591.
  Implementations **MUST** validate that decoded points are valid curve points and (for
  ciphersuites with non-trivial cofactor) lie in the prime-order subgroup.
- **The Point at Infinity**: The point at infinity, which is the identity element of the group, is represented by a byte
  array of the same length as a standard point encoding, but filled with all zero bytes. The point at infinity **MUST**
  be rejected when parsing VSS commitment points $C_{i,k}$, ephemeral public keys $E_i$, and static public keys $P_i$.
  Accepting identity elements in these positions would compromise protocol security.

#### Protocol Messages

The following messages are exchanged during the COCKTAIL-DKG protocol. They are constructed by concatenating the byte
representations of their constituent parts in the specified order.

**1. $msg_{1|i}$ (Participant -> Coordinator, Round 1)**

This message contains the participant's VSS commitment, their Proof-of-Possession, their ephemeral public key, and
one encrypted share per participant; including a self-share $c_{i,i}$ addressed to participant $i$ themselves. The 
self-share is encrypted under the same procedure as the others; including it keeps the message structure uniform, makes
the recovery procedure symmetric across the $n$ participants, and ensures every entry of the recipient-indexed bundle 
$C^{rec}_i$ is non-empty.

- $C_i$: The VSS commitment, which is a list of **exactly** $t$ elliptic curve points. Implementations **MUST** verify
  that the commitment contains exactly $t$ points; any other length indicates a malformed message or an attempted
  [threshold elevation attack](https://blog.trailofbits.com/2024/02/20/breaking-the-shared-key-in-threshold-signature-schemes/).
  - Format: $C_{i,0} \parallel C_{i,1} \parallel \cdots \parallel C_{i,t-1}$
- $PoP_i$: The Proof of Possession, which is a signature. The size depends on the signature scheme used by the
  ciphersuite.
- $E_i$: The ephemeral public key, an elliptic curve point.
  - It does not refer to isogenies. Here, E stands for "ephemeral".
- $c_{i,j}$: An encrypted ciphertext containing the secret share $s_{i,j}$ and an optional application-defined payload
  $payload_{i,j}$. The plaintext format is $s_{i,j} \parallel payload_{i,j}$, where $payload_{i,j}$ may be empty. The 
  ciphertext size depends on the AEAD scheme and the payload size. The minimum ciphertext size is the scalar encoding 
  size plus the AEAD authentication tag size (e.g., 32 + 16 = 48 bytes for most ciphersuites).
  
  Implementations **MUST** configure an upper bound `MAX_CIPHERTEXT_SIZE` on each individual ciphertext and
  **MUST** reject any framed ciphertext whose length prefix exceeds it; this is the resource-exhaustion
  mitigation referenced in $msg_{1|i}$, $msg_{2|i}$, and $C^{rec}_i$ parsing. The lower bound on
  `MAX_CIPHERTEXT_SIZE` itself is also normative:

  - **Conformance floor (MUST):** `MAX_CIPHERTEXT_SIZE` **MUST** be at least `scalar_size + AEAD_TAG_SIZE` (the
    exact size of a zero-payload encrypted share). An implementation whose configured `MAX_CIPHERTEXT_SIZE`
    setting causes it to reject ciphertexts of *exactly* this minimum size (and therefore reject zero-payload
    shares) is **non-conformant**. (Ciphertexts strictly *smaller* than this minimum are still **MUST**-rejected
    by the protocol-level checks at $msg_{1|i}$ parsing, $msg_{2|i}$ parsing, and recovery, because they cannot
    decrypt to a valid share at all; this conformance floor concerns the upper-bound cap, not the lower-bound
    size check.)
  - **Interoperability floor (SHOULD):** `MAX_CIPHERTEXT_SIZE` **SHOULD** be at least 65,536 bytes (64 KiB). This
    bound covers realistic application-payload sizes for the use cases COCKTAIL-DKG targets and is the
    recommended setting for general-purpose implementations.

  Above the SHOULD floor, the choice of `MAX_CIPHERTEXT_SIZE` is implementation- and deployment-defined.

  Each ciphertext is wire-framed as a fixed-width length prefix followed by the AEAD ciphertext bytes:
  $\widetilde{c_{i,j}} = len(c_{i,j}) \parallel c_{i,j}$, where $len(c_{i,j})$ is the byte length of $c_{i,j}$
  encoded as a **64-bit big-endian unsigned integer**. The framed form $\widetilde{c_{i,j}}$ is what appears in
  $msg_{1|i}$, $msg_{2|i}$, and the recovery bundle $C^{rec}_i$. Implementations **MUST** reject any framed
  ciphertext whose length prefix exceeds the implementation's `MAX_CIPHERTEXT_SIZE`.

The full message is the concatenation of these elements:

```math
msg_{1|i} = C_i \parallel PoP_i \parallel E_i \parallel \widetilde{c_{i,1}} \parallel \widetilde{c_{i,2}} \parallel \cdots \parallel \widetilde{c_{i,n}}
```

where each $\widetilde{c_{i,j}}$ is the length-prefixed ciphertext defined above. $C_i$, $PoP_i$, and $E_i$ are
fixed-length per the ciphersuite and are concatenated without additional framing.

**2. $msg2$ (Coordinator -> All Participants, Round 2)**

This message aggregates the public information from all participants and the ciphertexts addressed to the recipient.
It is equivalent to an ordered, recipient-specific projection of all Round 1 messages.

- $C_j$: The full VSS commitment from participant $j$, which is a list of **exactly** $t$ elliptic curve points.
- $PoP_j$: The Proof of Possession from participant $j$.
- $E_j$: The ephemeral public key from participant $j$.
- $c_{j,i}$: The ciphertext from participant $j$ intended for participant $i$.

The message broadcast to participant $i$ is structured as:

```math
msg_{2|i} = (C_1 \parallel PoP_1 \parallel E_1 \parallel \widetilde{c_{1,i}}) \parallel \cdots \parallel (C_n \parallel PoP_n \parallel E_n \parallel \widetilde{c_{n,i}})
```

where $\widetilde{c_{j,i}}$ is the length-prefixed framed ciphertext defined under $msg_{1|i}$ above. Concrete encodings
**MUST** preserve the participant ordering; $C_j$, $PoP_j$, and $E_j$ are fixed-length per the ciphersuite, and each 
$\widetilde{c_{j,i}}$ carries its own 64-bit big-endian length prefix, so the full message parses unambiguously.

Implementations **MAY** instead broadcast the complete ordered list of all $msg_{1|j}$ messages to every participant.

**3. $sig_i$ (Participant -> Coordinator, CertEq Phase)**

This message contains the participant's signature over the protocol transcript.

- $sig_i$: The signature, created using the participant's static private key $d_i$. The size depends on the signature
  scheme.

**4. Aggregated Signatures (Coordinator -> All Participants, CertEq Phase)**

This is the final message, containing all signatures on the transcript.

- $sig_j$: The signature from participant $j$.

The message is structured as:

```math
aggregated_sigs = sig_1 \parallel sig_2 \parallel \cdots \parallel sig_n
```

### Cryptographic Primitives

As COCKTAIL-DKG is intended to be used in conjunction with [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html), we
begin our enumeration of named hash functions with "H6".

## Protocol Definition

This section describes the COCKTAIL-DKG protocol in detail.

### Setup

Each participant $i$ is assumed to have:

- A unique identifier $i$ from $1$ to $n$. Identifiers **MUST** be the contiguous integers $1, 2, \ldots, n$ assigned to
  participants in a canonical, agreed-upon ordering, and all participants **MUST** agree on this ordering before the DKG
  begins; disagreement **MUST** be treated as a setup failure. The ordering is the same ordering used to list
  $P_1, \ldots, P_n$ throughout the protocol and the transcript. Identifiers **MUST NOT** be $0$ or congruent to $0$ 
  modulo the group order $q$, as this would allow a [zero share attack](https://www.zkdocs.com/docs/zkdocs/protocol-primitives/verifiable-secret-sharing/).
- The parameters $n$ (total participants) and $t$ (threshold). Both **MUST** satisfy $1 \le t \le n$ and
  $n \le 2^{32} - 1$ (the maximum representable in the transcript's `uint32_le` encoding of $n$ and $t$). $t = 1$
  corresponds to a $1$-of-$n$ deployment where any single participant can sign on behalf of the group; this is a 
  permitted-but-application-discouraged degenerate case (a single compromised participant can sign unilaterally, which
  defeats the threshold property). $t > n$, $t = 0$, $n = 0$, and any encoding that exceeds the 32-bit bound are invalid
  setups and participants **MUST** abort before Round 1.
- A long-term static key pair $(d_i, P_i)$.
- The ordered list of static public keys of all participants, ${P_1, P_2, \ldots, P_n}$ (including $P_i$ at index $i$).
  All $P_j$ **MUST** be distinct, valid prime-order subgroup points; participants **MUST** abort if any duplicate or 
  otherwise invalid public key is observed during setup.
- A ciphersuite defining the elliptic curve group, hash function, and AEAD scheme.
- A `context` string. The `context` is a normative input to several security properties of the protocol, including the
  freshness of ECDH-derived encryption keys, the prevention of cross-session replay, and the cross-protocol distinctness
  of PoP and CertEq signatures, so it **MUST** satisfy three requirements:

  1. **Session uniqueness.** The `context` **MUST** be unique to the DKG session, so that no two distinct DKG
     sessions ever share the same `context` value. Implementations typically achieve this by including a
     high-entropy random byte string, a timestamp, or a session ID in the `context` construction.
  2. **Participant binding.** The `context` **MUST** cryptographically bind the ordered participant identity
     set $(P_1, P_2, \ldots, P_n)$, so that an attempt to alter $n$, the participant ordering, or any $P_j$
     yields a different `context` value. This binding is what enables the PoP and CertEq signatures to be
     domain-separated from any other use of the participants' keys and prevents a malicious coordinator from
     reusing protocol messages across mismatched participant sets.
  3. **Ciphersuite binding.** The `context` **MUST** cryptographically bind the canonical `ciphersuite_id`
     byte string from the [Ciphersuite Definitions](#ciphersuite-definitions) normative table, so that
     ciphersuite confusion (the same byte material being reinterpreted under a different ciphersuite) is
     prevented. Implementations **MUST** use the exact `ciphersuite_id` byte string from that table (no
     whitespace normalization, no case folding, no alternate punctuation) wherever `ciphersuite_id` appears
     in the `context` construction.

  The **RECOMMENDED** construction that satisfies all three requirements is

  ```text
  context = H( "COCKTAIL-DKG-CONTEXT"
             || uint64_be(len(session_id))   || session_id
             || uint64_be(len(ciphersuite_id)) || ciphersuite_id
             || uint32_le(n)
             || P_1 || P_2 || ... || P_n )
  ```

  where $H$ is the ciphersuite's hash function, `session_id` is the session-unique byte string, the
  variable-length `session_id` and `ciphersuite_id` fields are each prefixed with their 64-bit big-endian byte
  length (the same wire-framing convention used for ciphertexts elsewhere in this spec), $n$ is included so
  the participant-list length is unambiguous, and each $P_j$ is encoded in the ciphersuite's compressed point
  encoding (fixed-length per ciphersuite). Any equivalent construction is permitted **provided** it satisfies
  all three MUSTs above; that is, it produces a distinct `context` per session, it unambiguously binds the
  ordered participant set with no tuple-boundary ambiguity between any two of its components, and it
  cryptographically binds the canonical `ciphersuite_id` byte string verbatim from the
  [Ciphersuite Definitions](#ciphersuite-definitions) table. Constructions that omit `ciphersuite_id`
  entirely from the hash preimage, normalize its bytes before hashing (e.g., lowercasing, whitespace
  collapsing, alternate punctuation), or substitute any other representation are **non-conformant**.
  Hashing the recommended preimage above, which contains the verbatim `ciphersuite_id` bytes as one of its
  length-framed inputs, is the recommended way to satisfy this MUST and is *not* an "omit/normalize" case.
  All participants **MUST** validate that they agree on the exact `context` byte string before proceeding;
  disagreement is a setup failure.

### Round 1: Commitment and Encryption

1. **Generate Polynomial:** Participant $i$ generates a secret polynomial $f_i(x)$ of degree $t-1$:
   $f_i(x) = a_{i,0} + a_{i,1}x + \cdots + a_{i,t-1}x^{t-1}$.
   
   The coefficients $a_{i,k}$ are chosen as random scalars via $RandomScalar()$. $a_{i,0}$ is the participant's
   primary secret share. If any sampled coefficient equals $0$ (probability $\approx 2^{-\lceil \log_2 q \rceil}$
   per coefficient, negligible in practice), implementations **MUST** resample that coefficient before continuing,
   so that every $C_{i,k} = a_{i,k} \cdot B$ is a non-identity point and the parsing rule at
   [Primitive Types](#primitive-types) rejecting identity VSS commitment points does not cause an honest abort.
2. **Compute VSS Commitment:** Participant $i$ computes a VSS commitment $C_i$ to their polynomial by creating a public
   commitment for each coefficient:
   $C_i = (C_{i,0}, C_{i,1}, \cdots, C_{i,t-1})$, where $C_{i,k} = a_{i,k} * B$.
3. **Generate Ephemeral Key:** Participant $i$ generates a fresh ephemeral key pair $(e_i, E_i)$ for this session
   with $e_i \leftarrow RandomScalar()$ and $E_i = e_i \cdot B$. If $e_i = 0$ (negligible probability),
   implementations **MUST** resample, so that $E_i$ is a non-identity point and the parsing rule at
   [Primitive Types](#primitive-types) rejecting identity ephemeral public keys does not cause an honest abort.
4. **Compute Proof of Possession (PoP):** Participant $i$ computes a digital signature $PoP_i$ over a concatenation of
   the `context` string, their VSS commitment $C_i$, and their ephemeral public key $E_i$. The signature is created
   using the secret $a_{i,0}$ as the private key and $C_{i,0}$ as the public key. The message to be signed is
   `context || C_i || E_i`, where $C_i$ is encoded as the byte concatenation
   $C_{i,0} \parallel C_{i,1} \parallel \cdots \parallel C_{i,t-1}$ (each point in the ciphersuite's compressed
   encoding, identical to its encoding in $msg_{1|i}$). The signature algorithm is the Schnorr scheme defined in
   [Schnorr Signature Scheme](#schnorr-signature-scheme). If `Sign` aborts at its step 3 due to $k = 0$
   (probability $\approx 2^{-\lceil \log_2 q \rceil}$, negligible), participant $i$ **MUST** treat this DKG
   session as locally failed: it **MUST NOT** send $msg_{1|i}$, **MUST NOT** publish any partially-derived
   value, and **MUST** abandon this session. To retry, participant $i$ joins a fresh DKG session with a
   different `context` string (which changes the `Sign` message $m$ and therefore the deterministic nonce $k$);
   simply resampling $a_{i,0}$ within the same context would require restarting Round 1 from step 1 and is
   indistinguishable from the participant dropping out, so a fresh-context retry is the recommended path. This
   is not a blameable misbehavior. The other participants observe only that participant $i$ failed to deliver
   $msg_{1|i}$ within the agreed timeout.
5. **Compute and Encrypt Shares:** For each participant $j$ from $1$ to $n$ (including $j = i$, the self-share):
    1. **Compute Share:** Participant $i$ computes the secret share $s_{i,j} = f_i(j)$.
    2. **Derive Key:** Participant $i$ computes two ECDH shared secrets: one with their ephemeral key and the
       recipient's static public key, and one with their static key and the recipient's static public key:
       $S^{(e)}_{i,j} = e_i * P_j$ and $S^{(d)}_{i,j} = d_i * P_j$. It then derives a symmetric key and nonce for the AEAD.
        - If the hash function has an output length of at least 56 bytes (448 bits):
            - $tmp = H6(S^{(e)}_{i,j} \parallel S^{(d)}_{i,j}, E_i, P_i, P_j, context)$.
            - $k_{i,j} = tmp[0:32]$
            - $iv_{i,j} = tmp[32:56]$
        - Otherwise:
            - $ikm = H6(S^{(e)}_{i,j} \parallel S^{(d)}_{i,j}, E_i, P_i, P_j, context)$.
            - $k_{i,j} = H("COCKTAIL-derive-key" \parallel ikm)$
            - $iv_{i,j} = H("COCKTAIL-derive-nonce" \parallel ikm)[0:24]$
            - Here, $H(x)$ is the underlying hash function (e.g., SHA-256).
    3. **Prepare Plaintext:** Participant $i$ prepares the plaintext to encrypt. This consists of the secret share
       $s_{i,j}$ followed by an optional application-defined payload $payload_{i,j}$:
       $plaintext_{i,j} = s_{i,j} \parallel payload_{i,j}$.
       If no application payload is used, $payload_{i,j}$ is empty.
    4. **Encrypt Share:** Participant $i$ encrypts the plaintext for participant $j$:
       $c_{i,j} = Enc(plaintext_{i,j}, k_{i,j}, iv_{i,j})$.
6. **Broadcast:** Participant $i$ sends their $msg_{1|i}$ to the coordinator.

### Round 2: Share Decryption and Verification

The coordinator waits to receive $msg_{1|i}$ from all $n$ participants. It then broadcasts a list of all received messages
to every participant. Upon receiving the list of all $msg_{1|i}$ messages, each participant $i$ performs the following
steps:

1. **Validate Commitments:** For each participant $j$ from $1$ to $n$:
    - Participant $i$ verifies that the VSS commitment $C_j$ contains **exactly** $t$ points. If $|C_j| \neq t$,
      participant $i$ **MUST** abort, identifying participant $j$ as malicious. This check prevents
      [threshold elevation attacks](https://blog.trailofbits.com/2024/02/20/breaking-the-shared-key-in-threshold-signature-schemes/).
2. **Verify All PoPs:** For each participant $j$ from $1$ to $n$:
    - Participant $i$ verifies the proof of possession $PoP_j$ using the Schnorr `Verify` algorithm. The signature is
      checked against the message `context || C_j || E_j` (with $C_j$ encoded as in Round 1), using participant $j$'s
      public commitment $C_{j,0}$ as the public key.
    - If any $PoP_j$ is invalid, participant $i$ **MUST** abort, identifying participant $j$ as malicious.
3. **Decrypt and Verify Shares:** For each participant $j$ from $1$ to $n$ (including the self-share $j = i$):
    1. **Derive Key:** Participant $i$ computes two ECDH shared secrets: one with the sender's ephemeral public key
       and their static key, and one with the sender's static public key and their static key:
       $S^{(e)}_{j,i} = d_i * E_j$ and $S^{(d)}_{j,i} = d_i * P_j$. They then derive the symmetric key and nonce:
        - If the hash function has an output length of at least 56 bytes (448 bits):
            - $tmp = H6(S^{(e)}_{j,i} \parallel S^{(d)}_{j,i}, E_j, P_j, P_i, context)$.
            - $k_{j,i} = tmp[0:32]$
            - $iv_{j,i} = tmp[32:56]$
        - Otherwise:
            - $ikm = H6(S^{(e)}_{j,i} \parallel S^{(d)}_{j,i}, E_j, P_j, P_i, context)$.
            - $k_{j,i} = H("COCKTAIL-derive-key" \parallel ikm)$
            - $iv_{j,i} = H("COCKTAIL-derive-nonce" \parallel ikm)[0:24]$
            - Here, $H(x)$ is the underlying hash function (e.g., SHA-256).
    2. **Decrypt Plaintext:** Participant $i$ decrypts the ciphertext sent to them from participant $j$:
       $plaintext_{j,i} = Dec(c_{j,i}, k_{j,i}, iv_{j,i})$.
       If decryption fails, participant $i$ **MUST** abort and report a decryption failure for the ciphertext
       attributed to participant $j$.
    3. **Parse Plaintext:** Participant $i$ parses the plaintext to extract the secret share $s_{j,i}$ (the first
       scalar-sized portion) and any optional application payload $payload_{j,i}$ (the remainder).
       If the plaintext is shorter than the ciphersuite's scalar encoding size, or if the leading scalar-sized
       portion does not decode to a valid scalar in $[0, q-1]$, participant $i$ **MUST** abort, identifying $j$
       as malicious.
    4. **Verify Share:** Participant $i$ verifies the decrypted share $s_{j,i}$ against $j$'s VSS commitment:
       $s_{j,i} * B = \sum_{k=0}^{t-1} i^k * C_{j,k}$
       If the check fails, participant $i$ **MUST** abort, identifying $j$ as malicious.
4.  **Compute Final Keys:** If all shares are successfully decrypted and verified:
    1. **Secret Share:** Participant $i$ computes their final long-lived secret share by summing all received shares:
       $x_i = \sum_{j=1}^{n} s_{j,i}$.
    2. **Group Public Key:** Participant $i$ computes the group public key:
       $Y = \sum_{j=1}^n C_{j,0}$.
    3. **Verification Share:** Participant $i$ computes their public verification share $Y_i$. This is done by first
       computing the aggregated commitment for each coefficient $k$:
       $C_{agg,k} = \sum_{j=1}^{n} C_{j,k}$.
       Then, $Y_i = \sum_{k=0}^{t-1} i^k * C_{agg,k}$.
    4. **Final Check:** Participant $i$ performs a final self-consistency check:
       $x_i * B = Y_i$. If this check fails, the participant **MUST** abort. Note: This check is mathematically
       guaranteed to pass if all VSS share verifications in step 3.4 succeeded. It serves as a defense-in-depth
       measure to catch implementation bugs in the share summation or verification share computation.

### Round 3: Certification

This round ensures that all honest participants have arrived at the same public state.

1. **Construct Transcript:** Each participant $i$ constructs a canonical byte representation of the final public
   transcript, $T$. The transcript **MUST** be constructed by concatenating the following elements in this exact order:
    1. $len(ciphersuite\_id)$: The length of the ciphersuite identifier string (e.g., `COCKTAIL(Ristretto255, SHA-512)`)
       as a little-endian 64-bit unsigned integer.
    2. $ciphersuite\_id$: The ciphersuite identifier as its UTF-8 byte representation. Including the ciphersuite
       identifier in the transcript makes the success certificate self-describing and prevents cross-ciphersuite
       confusion in audit and recovery tooling.
    3. $len(context)$: The length of the context string as a little-endian 64-bit unsigned integer.
    4. $context$: The context string bytes.
    5. $n$: The number of participants as a little-endian 32-bit unsigned integer.
    6. $t$: The threshold as a little-endian 32-bit unsigned integer.
    7. For $j$ from $1$ to $n$: $P_j$ (the static public key of participant $j$, in its standard encoding).
    8. For $j$ from $1$ to $n$: $C_j$ (the full VSS commitment of participant $j$: $C_{j,0} \parallel \cdots \parallel C_{j,t-1}$).
    9. For $j$ from $1$ to $n$: $PoP_j$ (the Proof of Possession signature from participant $j$).
    10. For $j$ from $1$ to $n$: $E_j$ (the ephemeral public key from participant $j$).
    11. $len(ext)$: The length of the application-specific extension as a little-endian 64-bit unsigned integer.
    12. $ext$: The application-specific extension bytes (may be empty).

   All participants **MUST** produce identical transcripts. Any difference indicates a split-view attack or implementation bug.
2. **Sign Transcript:** Participant $i$ signs the transcript $T$ with their long-term static private key $d_i$ using
   the Schnorr `Sign` algorithm, producing a signature $sig_i$. If `Sign` aborts at its step 3 due to $k = 0$
   (negligible probability), participant $i$ **MUST NOT** publish any partially-derived value and **MUST**
   treat this session as locally failed (analogous to the Round 1 PoP `k = 0` handling). Since the transcript
   $T$ is identical across all honest participants, restarting CertEq within the same DKG session would
   reproduce the same $(d_i, T)$ inputs to `Sign` and therefore the same $k = 0$ result; the only safe retry
   path is a fresh DKG session with a different `context` (which yields a different $T$).
3. **Broadcast Signature:** Participant $i$ sends $sig_i$ to the coordinator.
4. **Verify Certificate:** The coordinator broadcasts the set of all signatures ${sig_1, \cdots, sig_n}$ to everyone.
   Each participant $i$ verifies every signature $sig_j$ on the transcript $T$ against the public key $P_j$ using the
   Schnorr `Verify` algorithm.
5. **Success:** If all signatures are valid, the DKG is successful. The participant stores their secret share $x_i$ and
   the group public key $Y$. The collection of $T$ and all $n$ signatures on it is called a "success certificate" and
   can be stored for auditing.

### Application-Specific Extensions

COCKTAIL-DKG supports an optional application-specific extension that is appended to the transcript before signing.
This allows protocols that build atop COCKTAIL-DKG to ensure all parties agree on some application-defined value.

**Extension Format:**

The extension is appended to the transcript as:

- $len(ext)$: The length of the extension as a little-endian 64-bit unsigned integer.
- $ext$: The extension bytes (may be empty; when empty, $len(ext) = 0$).

**Recommended Use Cases:**

Applications **MAY** use the extension field for different purposes. Two common patterns are:

1. **Consensus on External State:** Ensure all parties commit to some agreed-upon value (e.g., a Merkle tree root,
   a configuration hash, or a session identifier). The protocol only succeeds if everyone provides the same extension
   value. This is useful when the DKG must be bound to external application state.

2. **Collective Randomness Derivation:** All participants hash together independently-contributed random data via the
   extension. If the transcript hashes all match, the participants can derive a shared random value that no single
   party could have predicted or biased. This is useful for protocols that need distributed randomness as a byproduct
   of the DKG.

These use cases are not compatible with each other; an application must choose one approach. The extension semantics
are entirely application-defined; COCKTAIL-DKG simply ensures that all participants agreed on the extension value
before the protocol completes.

**Deriving Extensions from Payloads:**

When applications use the optional payloads in the encryption step (see [Optional Application Payloads](#optional-application-payloads)),
they **MAY** derive the extension from those payloads to ensure all participants agree on the exchanged data. A recommended
approach is to compute a hash of the participant-ordered payloads:

1. For each participant $j$ from $1$ to $n$, collect their payload contributions. To produce a consistent extension
   across all participants, the application **MUST** ensure every recipient observes the same $payload_j$ from
   participant $j$ (e.g., by having $j$ broadcast the same payload to every recipient).
2. Compute the extension as:
   $ext = H(n \parallel len(payload_1) \parallel payload_1 \parallel \cdots \parallel len(payload_n) \parallel payload_n)$
   Where $H$ is the ciphersuite's hash function (the same $H$ used by $H6$), $n$ is encoded as a little-endian
   64-bit unsigned integer, and each $len(payload_j)$ is a little-endian 64-bit unsigned integer.

This ensures that any disagreement about the payloads will result in different transcripts and failed signature verification.

**Security Note:**

The extension is included in the transcript and thus covered by all participants' signatures. This provides the same
consensus guarantee as the rest of the transcript: if any participant has a different extension value, the signatures
will not verify and the protocol will abort safely.

## Error Handling

A robust implementation of COCKTAIL-DKG **MUST** handle a variety of error conditions. Errors can arise from malformed
messages, invalid cryptographic values, or protocol violations. The ability to distinguish between these cases is
crucial for security and usability.

### Error Categories

We recommend that implementations define distinct error types to represent different failure modes. This allows
applications to react appropriately, whether by retrying an operation, aborting the protocol, or initiating a
blame-finding procedure.

The following categories cover the most common errors:

1. **Parsing and Deserialization Errors**:
    - **Description**: These errors occur when a received message does not conform to the byte-based format specified in
      the `Message Formats` section. This could be due to an incorrect length, an invalid point or scalar encoding, or
      other structural defects.
    - **Action**: An honest participant should never produce a malformed message. If a participant receives such a
      message, it should be treated as evidence of a bug in the sender's implementation or a deliberate protocol
      violation. The protocol **MUST** be aborted. If the sender can be identified (e.g., in $msg_{1|i}$), they should
      be flagged as faulty.
2. **Cryptographic Verification Failures**:
    - **Description**: These errors occur when a cryptographic check fails. This category includes:
        - An invalid Proof-of-Possession ($PoP_j$).
        - A VSS share verification failure ($s_{j,i} \cdot B \ne \sum_{k=0}^{t-1} i^k \cdot C_{j,k}$).
        - A failed decryption of an encrypted share ($c_{j,i}$).
        - An invalid signature on the final transcript ($sig_j$).
    - **Action**: A cryptographic failure is a clear indication that a participant is behaving maliciously or has a
      serious bug. The protocol **MUST** be aborted immediately. For public failures such as an invalid PoP, invalid
      VSS share, or invalid transcript signature, the participant who sent the invalid data **MUST** be identified and
      blamed. A decryption failure is locally attributable to the sender's ciphertext, but it is **not** publicly
      verifiable in the same way as a VSS or PoP failure: the AEAD key derives from the recipient's static private
      key. See [Differences from ChillDKG](#5-ciphertexts-not-bound-by-the-transcript) for the option set:
      Options 1 and 2 establish only that a specific ciphertext was sent (ciphertext binding), while only Option 3
      provides public verification of the decryption outcome itself.
3. **Protocol Logic Errors**:
    - **Description**: These errors relate to violations of the protocol's state machine or rules, such as:
        - A participant sending a message at the wrong time.
        - The coordinator broadcasting an inconsistent `msg2` (e.g., omitting a participant's data).
    - **Action**: These errors indicate a faulty participant or coordinator. The protocol **MUST** be aborted.
      If the error can be traced to a specific participant, they should be blamed.

### Blame-Finding and Reporting

A key feature of a secure DKG protocol is the ability to identify malicious participants. When an error occurs, the
protocol **MUST** terminate and, when evidence permits, output information about who caused the failure. This is crucial
for accountability in decentralized systems.

- **Coordinator's Role**: The coordinator is positioned to *detect* errors in $msg_{1|i}$ messages early, but it
  is **not** trusted to *attribute* those errors, and the spec does not assume the coordinator is honest. When
  the coordinator receives a malformed $msg_{1|i}$ or one with an invalid PoP from participant $i$, it **MUST**
  abort the protocol and broadcast a blame message; however, the public verifiability of that blame depends on
  which part of $msg_{1|i}$ failed:
  - For an invalid $PoP_i$ or an invalid commitment-length check on $C_i$, the coordinator's blame can be
    publicly verified by any third party from the broadcast $C_i$, $PoP_i$, $E_i$, and the agreed `context`
    (the PoP signs $context \parallel C_i \parallel E_i$ under $C_{i,0}$, and the commitment-length check is
    purely structural). The coordinator's blame is therefore third-party-checkable evidence in this case.
  - For a malformed ciphertext frame in $msg_{1|i}$ (an out-of-range length prefix, undersize ciphertext,
    etc.) the coordinator cannot publicly attribute the malformation to participant $i$ without an
    application-level ciphertext-byte authentication mechanism (see
    [Differences from ChillDKG](#5-ciphertexts-not-bound-by-the-transcript)). The coordinator's blame in
    this case is unilateral and **MUST NOT** be relied upon as third-party-checkable evidence; participant
    $i$ may have sent a well-formed message that the coordinator subsequently modified. Applications
    requiring publicly-attributable malformed-ciphertext blame **MUST** layer such authentication.
- **Participant's Role and Public Proofs**: Participants **MUST** validate all data they receive.
  - If participant $i$ fails to verify a share $s_{j,i}$ from participant $j$, it **MUST** abort. To prove that $j$
    is cheating, participant $i$ can broadcast a blame message containing $j$'s index and the invalid share $s_{j,i}$.
    Any third party can then verify this claim by checking the VSS equation 
    ($s_{j,i} \cdot B = \sum_{k=0}^{t-1} i^k \cdot C_{j,k}$)
    using the public commitment $C_j$. A failure of this equation is a public and undeniable proof of $j$'s misbehavior.
  - Similarly, if a PoP from participant $j$ is invalid, this is also a publicly verifiable proof of misbehavior,
    since the PoP, the message it signs, and the public key $C_{j,0}$ are all public.
  - In contrast, a **decryption failure** at recipient $i$ for $c_{j,i}$ is *not* publicly verifiable in the same
    way: the AEAD verification requires the key $k_{j,i}$, which is derived from $i$'s static private key $d_i$
    and is not public. Recipient $i$ can locally attribute the failure to participant $j$'s ciphertext, but
    cannot produce a non-interactive proof that any third party can independently check from public data alone.
    Applications requiring publicly verifiable decryption-failure blame **MUST** use Option 3 from
    [Differences from ChillDKG](#5-ciphertexts-not-bound-by-the-transcript) (the dispute-evidence channel
    providing a non-interactive proof of decryption outcome); Options 1 and 2 establish only ciphertext
    binding and are not by themselves sufficient for public verification of the decryption outcome.
- **Resolving Disputes and Coordinator Malice**: The final certification round is essential for detecting a malicious
  coordinator and resolving disputes.
  - **Split-View Attack**: If a coordinator sends different messages to different participants, their final
    transcripts $T$ will differ. In Round 3, when participants exchange signatures, these signatures will not verify
    on the inconsistent transcripts.
    An honest participant $i$ who fails to verify $sig_j$ can initiate a dispute by broadcasting their $T_i$ and $sig_i$.
    - If participant $j$ responds with a different $T_j$ and a valid $sig_j$ over it, the discrepancy between $T_i$ and
      $T_j$ serves as undeniable proof of a split-view attack by the coordinator.
  - **Framing a Participant**: If a coordinator attempts to frame participant $j$ by modifying the
    PoP-bound portion of $msg_{1|j}$ (i.e., the VSS commitment $C_j$, the ephemeral public key $E_j$, or
    the PoP itself) before broadcasting it to the other participants, the modified PoP will fail PoP
    verification for all receivers, who will then abort Round 2 and broadcast a blame message naming $j$.
    Coordinator modifications restricted to the *ciphertext* portion of $msg_{1|j}$ (which the PoP does not
    sign; see [Differences from ChillDKG](#5-ciphertexts-not-bound-by-the-transcript)) do **not** cause
    PoP failure; they cause Round 2 framing-format or decryption failures whose attribution paths require
    Option 1 or Option 2 ciphertext-byte authentication for public blame. The rest of this paragraph addresses
    the PoP-bound-modification case only.

    The protocol does not reach Round 3, so the PoP-framing dispute cannot be resolved via the CertEq
    transcript-signature pathway. Instead, dispute resolution is **out-of-band evidence publication**:
    participant $j$, who locally still holds the original valid $msg_{1|j}$ (including its valid PoP signed
    under $C_{j,0}$), can publish that original message as a public refutation of the blame. Any third
    party can then verify the PoP against $C_{j,0}$ using the message bytes participant $j$ published; if
    it verifies, the conclusion is that the version received by other participants must have been altered
    in transit, definitively identifying the coordinator as malicious. This dispute-resolution channel is
    therefore a property of how the DKG embeds in the
    surrounding system (some broadcast surface participant $j$ can use to publish evidence), not a property of
    the in-protocol message flow. Applications that require automated, in-protocol dispute resolution
    **SHOULD** define such a refutation channel as part of their integration of COCKTAIL-DKG.

## Ciphersuites

This section describes the ciphersuites that are specified for use with COCKTAIL. The current scope includes both
[RFC 9591](https://www.rfc-editor.org/rfc/rfc9591.html#name-ciphersuites) and [ZIP-0312](https://zips.z.cash/zip-0312#ciphersuites).

Each ciphersuite defines a key derivation function $H6(x, E, P_s, P_r, extra)$, an encryption method
$Enc(plain, key, iv)$, and a decryption method $Dec(cipher, key, iv)$. Ciphersuites **MUST** use an AEAD mode for
$Enc()$ and $Dec()$. The protocol's confidentiality, ciphertext-integrity, blame-finding, and optional-payload
authentication properties all rely on AEAD; a non-AEAD $Enc()/Dec()$ pair is not a valid COCKTAIL-DKG ciphersuite.

The choice of AEAD is guided by the principle of preventing nonce reuse. **All COCKTAIL-DKG AEAD nonces are
deterministically derived via $H6$** (see [Round 1: Commitment and Encryption](#round-1-commitment-and-encryption));
implementations **MUST NOT** sample nonces randomly. The 24-byte (192-bit) nonce width was chosen so that the
$H6$-derived nonces have a negligible probability of collision across distinct $(sender, recipient, session)$
triples even though they are not random; i.e., the width is a safety margin for deterministic derivation,
not a license to sample nonces independently. For ciphersuites where the underlying hash function provides a
large enough output (at least 56 bytes / 448 bits; e.g., SHA-512), we can derive both the 256-bit key and the
24-byte nonce directly from a single $H6$ output.

For ciphersuites based on SHA-256, where the output is smaller than 56 bytes, we use $H6()$ to derive an Input Keying
Material (IKM), which is then used with the underlying hash function with two different prefixes. For the key, we use
$Sha256("COCKTAIL-derive-key" \parallel ikm)$. For the nonce, we use the most significant 192 bits of 
$Sha256("COCKTAIL-derive-nonce" \parallel ikm)$. The AEAD of choice for the SHA-256 based ciphersuites we specify here is
[XAES-256-GCM](https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md).

The $H6$ function is used to derive a symmetric key and nonce from ECDH shared secrets. Unless otherwise specified,
it is defined as:

$H6(x, E, P_s, P_r, extra) = H(prefix \parallel x \parallel E \parallel P_s \parallel P_r \parallel len(extra) \parallel extra)$

- $H$: The specified cryptographic hash function (e.g., SHA-512, BLAKE2b-512).
- $prefix$: A ciphersuite-specific byte string (e.g., `COCKTAIL-DKG-Ed25519-SHA512-H6`).
- $x$: The concatenation of two ECDH shared secrets: $S^{(e)}$ (ephemeral-to-static) and $S^{(d)}$ (static-to-static).
- $E$: The sender's ephemeral public key.
- $P_s$: The sender's static public key.
- $P_r$: The recipient's static public key.
- $len(extra)$: The length of the `extra` data, encoded as a little-endian 64-bit integer.
- $extra$: Additional context-specific data.

The output of $H6$ is used to derive the key and nonce for the AEAD.

### ECDH Shared-Secret Encoding

Each ECDH shared secret $S = s \cdot P$ (the scalar-mult result that is fed into $H6$ as part of
$x = S^{(e)} \parallel S^{(d)}$) is encoded as a fixed-length byte string per the ciphersuite, so that the
concatenation $x$ is unambiguously parsed and reproducible across implementations:

| Ciphersuite                     | ECDH encoding of $S = s \cdot P$                                                                                      | Size |
|---------------------------------|-----------------------------------------------------------------------------------------------------------------------|------|
| COCKTAIL(Ed25519, SHA-512)      | Canonical Ristretto255 encoding of $S$ ([RFC 9496 §4.3.2](https://www.rfc-editor.org/rfc/rfc9496.html#section-4.3.2)) | 32 B |
| COCKTAIL(Ristretto255, SHA-512) | Canonical Ristretto255 encoding of $S$ ([RFC 9496 §4.3.2](https://www.rfc-editor.org/rfc/rfc9496.html#section-4.3.2)) | 32 B |
| COCKTAIL(Ed448, SHAKE256)       | RFC 8032 compressed Ed448 encoding of $S$                                                                             | 57 B |
| COCKTAIL(P-256, SHA-256)        | SEC1 compressed point encoding of $S$                                                                                 | 33 B |
| COCKTAIL(secp256k1, SHA-256)    | SEC1 compressed point encoding of $S$                                                                                 | 33 B |
| COCKTAIL(JubJub, BLAKE2b-512)   | ZIP-0312 `SerializeElement` of $S$ (32-byte little-endian, y-parity)                                                  | 32 B |
| COCKTAIL(Pallas, BLAKE2b-512)   | Halo2/Orchard compressed encoding of $S$ (32-byte little-endian, y-parity)                                            | 32 B |

For **Curve25519-family ciphersuites** (COCKTAIL(Ed25519, SHA-512), COCKTAIL(Ristretto255, SHA-512)), the ECDH
shared secret is the canonical 32-byte Ristretto255 encoding of $S = s \cdot P$ as defined in [RFC 9496 §4.3.2](https://www.rfc-editor.org/rfc/rfc9496.html#section-4.3.2).
Both ciphersuites operate internally over Ristretto255 (see
[Working with curves with small subgroups](#working-with-curves-with-small-subgroups)) and therefore produce
byte-identical ECDH shared secrets for equal scalar/point inputs; the ciphersuites are domain-separated only via
their distinct $H6$, $H7$, and nonce prefixes.

For **Ed448 ciphersuites** (COCKTAIL(Ed448, SHAKE256)), the ECDH shared secret is the 57-byte RFC 8032
compressed Ed448 encoding of $S = s \cdot P$. Because all decoded protocol points are required to be non-identity
prime-order subgroup points, $S$ is computed inside the prime-order subgroup and has a unique compressed Ed448
encoding. Decaf448-internal implementations use the deterministic Decaf448-to-Ed448 output mapping defined in the
COCKTAIL(Ed448, SHAKE256) ciphersuite definition before feeding $S$ into $H6$.

For **Weierstrass-curve ciphersuites** (COCKTAIL(P-256, SHA-256), COCKTAIL(secp256k1, SHA-256)), the ECDH shared
secret is the SEC1 compressed encoding of $S = s \cdot P$: a one-byte tag $\{0x02, 0x03\}$ indicating the parity
of $S$'s $y$-coordinate, followed by the 32-byte big-endian encoding of $S$'s $x$-coordinate.

For **Zcash-family ciphersuites** (COCKTAIL(JubJub, BLAKE2b-512), COCKTAIL(Pallas, BLAKE2b-512)), the ECDH
shared secret is the standard Zcash compressed encoding of $S$, with conventions that differ between JubJub and
Pallas:

- **JubJub** (a twisted Edwards curve): use the Edwards-style 32-byte encoding defined by
  [ZIP-0312](https://zips.z.cash/zip-0312) (`repr_J` / `SerializeElement`), which encodes the affine
  $y$-coordinate of $S$ as a 32-byte little-endian integer with the sign bit of $x$ packed into the high bit of
  the encoded $y$. This is the same encoding used for Jubjub elements throughout Zcash Sapling.
- **Pallas** (a short-Weierstrass curve on the Pasta cycle): use the Halo2/Orchard `to_bytes` convention, which
  encodes the affine $x$-coordinate of $S$ as a 32-byte little-endian integer with the sign bit of $y$ packed
  into the high bit of the encoded $x$.

Both are 32-byte canonical encodings; implementations **MUST** use the curve-appropriate convention and **MUST
NOT** confuse them.

In every case, the encoding **MUST** be canonical (a single byte representation per element); non-canonical
encodings **MUST** be rejected by the recipient on decode of $S$ when $S$ is exchanged outside this protocol.
Within COCKTAIL-DKG itself, each side computes its own $S$ locally and encodes it deterministically, so the
encoded value is byte-identical on the sender and recipient sides by construction.

### Ciphersuite Definitions

Each ciphersuite is identified by a **canonical `ciphersuite_id` string**. The `ciphersuite_id` is
consensus-critical: it is bound into the session `context`, the canonical transcript $T$, the test-vector
labeled-hash derivation, and per-implementation domain separation. Implementations **MUST** use the exact
byte representations below (no whitespace normalization, no case folding, no alternate punctuation); the
strings are UTF-8 encoded but happen to be pure ASCII.

| Ciphersuite group              | `ciphersuite_id` byte string                                 |
|--------------------------------|--------------------------------------------------------------|
| Ed25519 / SHA-512              | `COCKTAIL(Ed25519, SHA-512)`                                 |
| Ristretto255 / SHA-512         | `COCKTAIL(Ristretto255, SHA-512)`                            |
| Ed448 / SHAKE256               | `COCKTAIL(Ed448, SHAKE256)`                                  |
| P-256 / SHA-256                | `COCKTAIL(P-256, SHA-256)`                                   |
| secp256k1 / SHA-256            | `COCKTAIL(secp256k1, SHA-256)`                               |
| JubJub / BLAKE2b-512           | `COCKTAIL(JubJub, BLAKE2b-512)`                              |
| Pallas / BLAKE2b-512           | `COCKTAIL(Pallas, BLAKE2b-512)`                              |

Implementations **MUST** reject any transcript whose `ciphersuite_id` field, which appears as explicit
length-prefixed bytes at the head of $T$ (see [Round 3: Certification](#round-3-certification)), does not
exactly match one of the byte strings above. For the session `context`, which under the recommended
construction is a hash digest over a preimage that includes `ciphersuite_id` rather than the raw
`ciphersuite_id` bytes, the corresponding check is structural: implementations **MUST** ensure their own
`context` preimage uses the exact `ciphersuite_id` byte string for the ciphersuite they believe they are
running, and **MUST** abort if any participant's reconstructed `context` value disagrees with the one they
themselves derived (cf. [Setup](#setup), where context-agreement is already a MUST). For implementations
using a non-hashing `context` construction in which `ciphersuite_id` appears as an explicit substring, the
direct byte-string match above applies.

- **COCKTAIL(Ed25519, SHA-512)**
  - **Group (mathematical)**: the prime-order subgroup of order $L$ of Edwards25519. Implementations **MAY**
    realize this group via either of two equivalent strategies: the choice is local and does not affect
    interoperability, because both produce byte-identical outputs for byte-identical inputs:
    - **(a) Ristretto255-internal.** Represent group elements as Ristretto255 elements (RFC 9496). All scalar
      arithmetic and ECDH operations execute over Ristretto255, which mathematically abstracts away Edwards25519's
      cofactor structure. Inputs received as 32-byte RFC 8032 Ed25519 byte strings are decoded to
      `CompressedEdwardsY`, decompressed, and the resulting Edwards point is **then** required to be in the
      prime-order subgroup (see "Input requirements" below); only those prime-order-subgroup points have a
      meaningful Ristretto255 representative. Outputs for Ed25519 consumers are emitted via the deterministic
      three-step output mapping defined below.
    - **(b) Raw-Edwards-with-subgroup-check.** Represent group elements as Edwards25519 points directly. All
      scalar arithmetic and ECDH operations execute on the prime-order subgroup of order $L$, which is closed
      under the protocol's operations. All decoded input points **MUST** be checked to be in the prime-order
      subgroup before use (see "Input requirements" below); raw cofactor-bearing Edwards points are rejected
      on input. Outputs are emitted via direct RFC 8032 Ed25519 encoding of the resulting prime-order Edwards
      point.

    Strategies (a) and (b) are byte-equivalent: Ristretto255 is the canonical bijection between the prime-order
    subgroup of Edwards25519 and the Ristretto255 group, so scalar arithmetic in either form produces the same
    Edwards point, and the RFC 8032 encoding of that Edwards point is the same in either case. The
    Ristretto255-internal strategy (a) has the advantage that prime-order safety is structural: non-prime-order
    elements cannot even be represented as Ristretto255 values, so the subgroup check is implicit; the
    raw-Edwards strategy (b) is simpler to implement on top of existing Ed25519 libraries but requires explicit
    subgroup checks on every decoded input.

  - **Input requirements**: regardless of implementation strategy, every decoded Edwards25519 input point
    (static public keys $P_i$, ephemeral public keys $E_i$, VSS commitment points $C_{i,k}$, Schnorr commitment
    points $R$) **MUST** be verified to lie in the prime-order subgroup of order $L$. The check is either
    explicit (multiply by $L$ and assert identity, or use a library-provided `is_torsion_free` predicate) or
    implicit via the Ristretto255 abstraction (decode failure when the candidate Edwards point is not the
    canonical Ristretto255 representative). Implementations **MUST** abort on subgroup-check failure.

  - **Output format**: the group public key $Y$ and verification shares $Y_i$ are emitted as 32-byte
    RFC 8032 Ed25519 compressed point encodings (the affine $y$-coordinate as a 32-byte little-endian integer
    with the sign bit of $x$ packed into the high bit of the last byte). Strategy (b) implementations encode
    the result directly. Strategy (a) implementations **MUST** apply the following deterministic three-step
    output mapping (which produces the same bytes), and **MUST NOT** substitute an implementation-internal
    Edwards representative or any older cofactor-clearing formula:

    1. Encode the Ristretto255 element $R$ to its canonical 32-byte Ristretto255 encoding per [RFC 9496 §4.3.2](https://www.rfc-editor.org/rfc/rfc9496.html#section-4.3.2).
    2. Decode those 32 bytes per [RFC 9496 §4.3.1](https://www.rfc-editor.org/rfc/rfc9496.html#section-4.3.1)
       (the canonical decoding procedure). RFC 9496's decoding returns a specific Edwards point on Edwards25519
       in the prime-order subgroup of order $q$. This Edwards point is the canonical Ed25519 representative of 
       $R$ and is uniquely determined by the Ristretto255 byte encoding from step 1.
    3. Encode that Edwards point as the standard 32-byte [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html) 
       Ed25519 compressed point encoding: the affine $y$-coordinate written as a 32-byte little-endian integer 
       with the sign bit of $x$ packed into the high bit of the last byte.

    Because step 1 and step 2 are both canonical and deterministic, two independent implementations that
    compute the same Ristretto255 element internally (regardless of their internal Edwards representative)
    will produce byte-identical 32-byte Ed25519 outputs. The generic cofactor-clearing identity discussed in
    [Working with curves with small subgroups](#working-with-curves-with-small-subgroups) is **not** part of
    this output lift and **MUST NOT** be substituted for the RFC 9496-based procedure above; the Edwards
    point returned by [RFC 9496 §4.3.1](https://www.rfc-editor.org/rfc/rfc9496.html#section-4.3.1) is already
    in the prime-order subgroup, and using a separate cofactor-clearing step would also fail to pin down a 
    canonical Edwards representative across implementations.

    Secret shares $x_i$ are scalars and **MUST** be emitted in the 32-byte little-endian RFC 8032 Ed25519
    scalar encoding without transformation (the numerical scalar is the same as the underlying Ristretto255
    scalar; only the byte ordering matches RFC 8032's little-endian convention).
  - **`H6` Hash**: SHA-512
  - **`H6` Prefix**: `COCKTAIL-DKG-Ed25519-SHA512-H6` (distinct from the Ristretto255 ciphersuite below)
  - **Key/Nonce**: The first 32 bytes of the `H6` output are the key, and the next 24 bytes are the nonce.
  - **AEAD**: XChaCha20-Poly1305

- **COCKTAIL(Ristretto255, SHA-512)**
  - **Group**: Ristretto255 (RFC 9496). All scalar arithmetic, ECDH operations, and outputs (group public key,
    verification shares) are encoded as Ristretto255 elements. No cross-abstraction lift to raw Ed25519 is
    performed; this ciphersuite is for consumers that natively use Ristretto255.
  - **`H6` Hash**: SHA-512
  - **`H6` Prefix**: `COCKTAIL-DKG-Ristretto255-SHA512-H6` (distinct from the Ed25519 ciphersuite above)
  - **Key/Nonce**: The first 32 bytes of the `H6` output are the key, and the next 24 bytes are the nonce.
  - **AEAD**: XChaCha20-Poly1305

- **COCKTAIL(Ed448, SHAKE256)**
  - **Group**: the prime-order subgroup of Edwards448, with RFC 9591 / RFC 8032 encodings. This ciphersuite is
    intended for interoperability with RFC 9591 `FROST(Ed448, SHAKE256)` key material. Implementations **MAY**
    realize this group via either of two equivalent strategies:
    - **(a) Decaf448-internal.** Represent group elements internally as Decaf448 elements (RFC 9496). Received
      57-byte RFC 8032 Ed448 point encodings are decoded as Edwards448 points, required to be in the prime-order
      subgroup, and then represented in the Decaf448 quotient. Outputs are emitted via the deterministic output
      mapping below.
    - **(b) Raw-Edwards-with-subgroup-check.** Represent group elements as Edwards448 points directly. All decoded
      input points **MUST** be checked to be in the prime-order subgroup before use. Outputs are emitted via direct
      RFC 8032 Ed448 encoding of the resulting prime-order Edwards point.

    Strategies (a) and (b) are byte-equivalent for all protocol outputs. The prime-order Edwards448 subgroup maps
    isomorphically to Decaf448, and the output mapping below projects the Decaf448 result back to that subgroup
    before RFC 8032 encoding.
  - **Input requirements**: every decoded Ed448 input point (static public keys $P_i$, ephemeral public keys $E_i$,
    VSS commitment points $C_{i,k}$, Schnorr commitment points $R$, group public key $Y$, and verification shares
    $Y_i$ when imported) **MUST** be verified to lie in the prime-order subgroup of order $q$ and **MUST NOT** be
    the identity. Implementations **MUST** abort on subgroup-check failure. Cofactor clearing alone is not an
    acceptable substitute for subgroup validation.
  - **Output format**: the group public key $Y$ and verification shares $Y_i$ are emitted as 57-byte RFC 8032
    Ed448 compressed point encodings, matching RFC 9591 `SerializeElement`. Strategy (b) implementations encode
    the result directly. Strategy (a) implementations **MUST** apply the following deterministic output mapping:

    1. Encode the Decaf448 element $D$ to its canonical 56-byte Decaf448 encoding per [RFC 9496 §5.3.2](https://www.rfc-editor.org/rfc/rfc9496.html#section-5.3.2).
    2. Decode those 56 bytes per [RFC 9496 §5.3.1](https://www.rfc-editor.org/rfc/rfc9496.html#section-5.3.1).
       RFC 9496's decoding procedure returns a specific internal Edwards448 representative `P = (x, y, 1, t)` 
       of the Decaf448 element.
    3. Project that representative into the prime-order Edwards448 subgroup:
       $P' = [4^{-1} \bmod q] \cdot ([4] \cdot P)$.
    4. Encode $P'$ as the standard 57-byte RFC 8032 Ed448 compressed point encoding.

    Because steps 1 through 3 are canonical and deterministic, two independent Decaf448-internal implementations
    that compute the same Decaf448 element will produce byte-identical 57-byte Ed448 outputs in the prime-order
    subgroup. Plain cofactor clearing $[4] \cdot P$ is **not** this output lift and **MUST NOT** be substituted for
    the projection above, because it would multiply the prime-order component by 4 rather than recover the RFC
    9591-compatible subgroup representative.
  - **Scalar encoding**: 57-byte little-endian scalar encoding, matching RFC 9591 `SerializeScalar`. Encoded scalars
    **MUST** be canonical values in $[0, q-1]$.
  - **`H6` Hash**: SHAKE256 invoked at 56-byte output. (SHAKE256 is an XOF; $HashToScalar$ for this ciphersuite
    invokes SHAKE256 at 114 bytes, which is a separate use of the same primitive. See
    [Schnorr Hash-to-Scalar Reduction](#schnorr-hash-to-scalar-reduction).)
  - **`H6` Prefix**: `COCKTAIL-DKG-Ed448-SHAKE256-H6`
  - **Key/Nonce**: The 56-byte $H6$ output is the key (first 32 bytes) followed by the nonce (next 24 bytes).
  - **AEAD**: XChaCha20-Poly1305
  - **RFC 9591 compatibility note**: the DKG outputs (group public key $Y$, verification shares $Y_i$, and secret
    shares $x_i$) use the same raw Ed448 point and scalar encodings as RFC 9591. The additional COCKTAIL-DKG
    Schnorr signatures used for PoPs and transcript certification remain COCKTAIL-specific and are domain-separated
    from RFC 9591 signing.

- **COCKTAIL(P-256, SHA-256)**
  - **`H6` Hash**: SHA-256
  - **`H6` Prefix**: `COCKTAIL-DKG-P256-SHA256-H6`
  - **Key/Nonce**: The output of `H6` is used as an input key material.
    - The key **MUST** be `SHA-256("COCKTAIL-derive-key" || IKM)` (the full 32-byte SHA-256 output).
    - The nonce **MUST** be the first 24 bytes of `SHA-256("COCKTAIL-derive-nonce" || IKM)`.
  - **AEAD**: [XAES-256-GCM](https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md)

- **COCKTAIL(secp256k1, SHA-256)**
  - **Note**: This ciphersuite is **NOT** backwards-compatible with ChillDKG due to our key derivation including both
    ephemeral-static and static-static ECDH, instead of just ephemeral-static (see 
    [Differences from ChillDKG](#differences-from-chilldkg) below).
  - **`H6` Definition**: A BIP-340-style tagged hash with the tag `COCKTAIL-DKG/H6`.
    The message is $x \parallel E \parallel P_s \parallel P_r \parallel extra$.
    Note that this deviates from the default `H6` formula above by omitting `len(extra)`. This is safe in COCKTAIL-DKG
    because $extra$ is always the session `context` and is fixed across every $H6$ call within a session, so no
    parsing ambiguity can arise. Applications **MUST NOT** repurpose this $H6$ with variable-length `extra` inputs
    without re-introducing length prefixing.
  - **Key/Nonce**: The output of `H6` is used as an input key material.
    - The key **MUST** be `SHA-256("COCKTAIL-derive-key" || IKM)` (the full 32-byte SHA-256 output).
    - The nonce **MUST** be the first 24 bytes of `SHA-256("COCKTAIL-derive-nonce" || IKM)`.
  - **AEAD**: [XAES-256-GCM](https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md)
  - **Bitcoin Taproot Warning**: When using this ciphersuite for Bitcoin Taproot outputs, applications **MUST** be aware
    that a malicious participant could attempt to embed a hidden Taproot script-path commitment in the threshold public
    key. Applications intending to use the group public key $Y$ as a Taproot output **MUST** apply the BIP-341
    unspendable-script-path tweak (as described in ChillDKG) when constructing the Taproot output key from $Y$. This
    is the only mitigation specified by this document; an operational policy of "only spend via the key path" is
    **not** sufficient, because once $Y$ is published as the Taproot output key, an attacker who knows the hidden
    script path can spend via that path without the operator's involvement. This consideration is specific to Bitcoin
    Taproot and does not apply to other uses of this ciphersuite.

- **COCKTAIL(JubJub, BLAKE2b-512)**
  - **Note**: Compatible with [ZIP-0312](https://zips.z.cash/zip-0312#ciphersuites).
  - **`H6` Hash**: BLAKE2b-512 (full 64-byte output; $H6$ uses the first 56 bytes).
  - **`H6` Prefix**: `COCKTAIL-DKG-JubJub-BLAKE2b-H6`
  - **Key/Nonce**: The first 32 bytes of the `H6` output are the key, and the next 24 bytes are the nonce.
    The trailing 8 bytes of the BLAKE2b-512 output are unused for $H6$.
  - **AEAD**: XChaCha20-Poly1305

- **COCKTAIL(Pallas, BLAKE2b-512)**
  - **Note**: Compatible with [ZIP-0312](https://zips.z.cash/zip-0312#ciphersuites).
  - **`H6` Hash**: BLAKE2b-512 (full 64-byte output; $H6$ uses the first 56 bytes).
  - **`H6` Prefix**: `COCKTAIL-DKG-Pallas-BLAKE2b-H6`
  - **Key/Nonce**: The first 32 bytes of the `H6` output are the key, and the next 24 bytes are the nonce.
    The trailing 8 bytes of the BLAKE2b-512 output are unused for $H6$.
  - **AEAD**: XChaCha20-Poly1305

### Schnorr Signature Scheme

COCKTAIL-DKG uses a simple Schnorr signature scheme for both the Proof of Possession (PoP) and the transcript 
certification in Round 3. The signature scheme is defined as follows:

#### Schnorr Signature Format

A signature consists of two components:

- $R$: A compressed elliptic curve point (the commitment)
- $z$: A scalar (the response)

The signature is encoded as the concatenation of the compressed point encoding of $R$ followed by the scalar encoding
of $z$. The total signature size is the point size plus the scalar size for the ciphersuite's group:

| Ciphersuite group              | Point size | Scalar size | Signature size |
|--------------------------------|-----------:|------------:|---------------:|
| Ristretto255 / Ed25519         | 32 bytes   | 32 bytes    | 64 bytes       |
| Ed448                          | 57 bytes   | 57 bytes    | 114 bytes      |
| P-256 / secp256k1              | 33 bytes   | 32 bytes    | 65 bytes       |
| JubJub                         | 32 bytes   | 32 bytes    | 64 bytes       |
| Pallas                         | 32 bytes   | 32 bytes    | 64 bytes       |

#### Schnorr Sign Algorithm

Given a secret key $sk$ (a scalar) and a message $m$ (a byte string):

1. Compute the public key: $pk = sk * B$
2. Compute a deterministic nonce: $k = HashToScalar(prefix_{nonce} \parallel encode(sk) \parallel m)$
3. **Reject $k = 0$**: if $k = 0$ (probability $\approx 2^{-\lceil \log_2 q \rceil}$, negligible),
   implementations **MUST** abort signing immediately and **MUST NOT** reveal any further derived value. A $k = 0$
   would yield $R = O$ (the identity), which the `Verify` algorithm rejects at step 2, but the response
   $z = k + c \cdot sk = c \cdot sk$ would also be computable from the signer's outputs and would directly leak
   $sk$ to any observer who saw $z$. Since the nonce is deterministic, a signer who hits this branch on a given
   $(sk, m)$ pair **MUST NOT** simply retry with the same inputs; this is treated as an unrecoverable signing
   failure for this $(sk, m)$ pair. Applications **MAY** introduce an additional disambiguator (e.g., a 32-byte
   counter mixed into $prefix_{nonce}$) as an out-of-band recovery mechanism, but the base scheme aborts.
4. Compute the commitment: $R = k * B$
5. Compute the challenge: $c = HashToScalar(prefix_{H7} \parallel R \parallel pk \parallel m)$
6. Compute the response: $z = k + c \cdot sk \bmod q$
7. Return the signature $(R, z)$

Where:

- $prefix_{nonce}$ and $prefix_{H7}$ are ciphersuite-specific UTF-8 byte strings (e.g.,
  `COCKTAIL-DKG-Ed25519-SHA512-NONCE` and `COCKTAIL-DKG-Ed25519-SHA512-H7`). They provide domain separation between
  COCKTAIL-DKG signatures and any standard signature scheme that uses the ciphersuite's underlying hash, so that
  COCKTAIL-DKG signatures cannot be re-verified by a verifier of the ciphersuite's underlying signature scheme
  (e.g., EdDSA, BIP-340).
- $encode(\cdot)$ uses the ciphersuite's compressed point encoding for points and the ciphersuite's scalar encoding
  for scalars.
- $B$ is the generator point of the elliptic curve group.
- $HashToScalar$ is defined per ciphersuite in [Schnorr Hash-to-Scalar Reduction](#schnorr-hash-to-scalar-reduction)
  and has a fully specified, deterministic structure per ciphersuite. For most ciphersuites this is a single
  hash invocation followed by wide modular reduction; for P-256 specifically, $HashToScalar$ is a 48-byte
  expansion via two SHA-256 invocations with distinct one-byte prefixes (see the P-256 row of
  [Schnorr Hash-to-Scalar Reduction](#schnorr-hash-to-scalar-reduction)), and for secp256k1 it is a single
  SHA-256 invocation reduced modulo $q$ (BIP-340 conventions). In every case, the byte string passed into
  $HashToScalar$ is consumed by the ciphersuite's defined hash structure exactly once before reduction; no
  additional outer/inner hash wrap is applied by `Sign` or `Verify`.

#### Schnorr Verify Algorithm

Given a signature $(R, z)$, a public key $pk$, and a message $m$:

1. Reject if $z$ does not decode to a canonical scalar in $[0, q-1]$.
2. Reject if $R$ does not decode to a valid prime-order subgroup point that is not the identity.
3. Compute the challenge: $c = HashToScalar(prefix_{H7} \parallel R \parallel pk \parallel m)$
4. Compute the left-hand side: $lhs = z * B$
5. Compute the right-hand side: $rhs = R + c * pk$
6. Return `true` if $lhs = rhs$, otherwise return `false`

#### Schnorr Prefix Strings

The ciphersuite-specific values for $prefix_{H7}$ and $prefix_{nonce}$ are:

| Ciphersuite                     | $prefix_{H7}$                         | $prefix_{nonce}$                         |
|---------------------------------|---------------------------------------|------------------------------------------|
| COCKTAIL(Ed25519, SHA-512)      | `COCKTAIL-DKG-Ed25519-SHA512-H7`      | `COCKTAIL-DKG-Ed25519-SHA512-NONCE`      |
| COCKTAIL(Ristretto255, SHA-512) | `COCKTAIL-DKG-Ristretto255-SHA512-H7` | `COCKTAIL-DKG-Ristretto255-SHA512-NONCE` |
| COCKTAIL(Ed448, SHAKE256)       | `COCKTAIL-DKG-Ed448-SHAKE256-H7`      | `COCKTAIL-DKG-Ed448-SHAKE256-NONCE`      |
| COCKTAIL(P-256, SHA-256)        | `COCKTAIL-DKG-P256-SHA256-H7`         | `COCKTAIL-DKG-P256-SHA256-NONCE`         |
| COCKTAIL(secp256k1, SHA-256)    | (BIP-340 tagged hash; see below)      | (BIP-340 tagged hash; see below)         |
| COCKTAIL(JubJub, BLAKE2b-512)   | `COCKTAIL-DKG-JubJub-BLAKE2b-H7`      | `COCKTAIL-DKG-JubJub-BLAKE2b-NONCE`      |
| COCKTAIL(Pallas, BLAKE2b-512)   | `COCKTAIL-DKG-Pallas-BLAKE2b-H7`      | `COCKTAIL-DKG-Pallas-BLAKE2b-NONCE`      |

For the secp256k1 ciphersuite, the nonce and challenge derivations use BIP-340 tagged hashes directly and
**MUST** override (not wrap) the generic `Sign` step 2 and step 5 formulas above. The $k = 0$ rejection rule from
`Sign` step 3 also applies (and aborts under the same conditions):

- **Nonce** (replaces step 2): $k = OS2IP(taggedHash(\text{`COCKTAIL-DKG/NONCE'}, encode(sk) \parallel m)) \bmod q$.
- **Challenge** (replaces step 5): $c = OS2IP(taggedHash(\text{`COCKTAIL-DKG/H7'}, R \parallel pk \parallel m)) \bmod q$.

Where $taggedHash(tag, msg) = SHA256(SHA256(tag) \parallel SHA256(tag) \parallel msg)$ as defined in BIP-340, $tag$ is
encoded as its UTF-8 byte representation, $encode(sk)$ is the 32-byte big-endian secp256k1 scalar encoding, and
$OS2IP$ interprets the 32-byte tagged-hash output as a big-endian integer. The same `Verify` step 3 substitution
applies. The resulting scalar bias is approximately $2^{-128}$ (specifically $\approx 1.27 \cdot 2^{-128}$) for
secp256k1 because $q \approx 2^{256} - 2^{128}$.

#### Schnorr Hash-to-Scalar Reduction

$HashToScalar$ takes a byte string $input$ and reduces it to a scalar in $[0, q-1]$. The construction depends on the
ciphersuite's hash output length and on the ratio between $2^{8L}$ (where $L$ is the hash output byte-length) and $q$:

- **SHA-512 (Ed25519, Ristretto255)**: invoke SHA-512 on $input$ to produce 64 bytes; interpret the bytes as the
  ciphersuite's scalar endianness and apply wide reduction modulo $q$. Bias $\le 2^{-128}$.
- **SHAKE256 (Ed448)**: invoke SHAKE256 on $input$ with a 114-byte output (chosen so the input to the
  reduction is at least $\lceil \log_2 q \rceil + 128$ bits); interpret as little-endian and apply wide reduction
  modulo $q$. Bias $\le 2^{-128}$. Note that SHAKE256 is an extendable-output function; H6 invokes SHAKE256 at
  56 bytes for AEAD key/nonce derivation, while $HashToScalar$ invokes SHAKE256 at 114 bytes. These are independent
  uses of the same primitive at different output lengths.
- **BLAKE2b-512 (JubJub, Pallas)**: invoke BLAKE2b-512 on $input$ to produce 64 bytes; interpret as little-endian and
  apply wide reduction modulo $q$. Bias $\le 2^{-128}$.
- **SHA-256, P-256**: P-256's order is $q \approx 2^{256} - 2^{224}$, so direct mod-$q$ reduction of a 32-byte hash
  has statistical distance from uniform of $\approx 2^{-32}$, which is too large for a 128-bit security target.
  $HashToScalar$ for P-256 therefore expands to 48 bytes before reduction:
  $HashToScalar(input) = OS2IP\bigl(SHA256(\mathtt{0x01} \parallel input) \parallel SHA256(\mathtt{0x02} \parallel input)[0{:}16]\bigr) \bmod q$,
  where $OS2IP$ interprets the 48-byte string as a big-endian integer. Bias $\le 2^{-128}$. This matches the spirit
  of `hash_to_field` from RFC 9380 used by RFC 9591's FROST(P-256, SHA-256).
- **SHA-256, secp256k1**: secp256k1's order is $q \approx 2^{256} - 2^{128}$, so direct mod-$q$ reduction of a
  32-byte hash has bias $\approx 1.27 \cdot 2^{-128}$ (i.e., the leftover $2^{256} \bmod q$ divided by $2^{256}$).
  $HashToScalar(input) = OS2IP(SHA256(input)) \bmod q$, interpreted big-endian. This matches BIP-340 conventions
  and is acceptable for 128-bit security targets.

#### Schnorr Security Notes

- **Domain separation from underlying signatures**: The challenge is computed by hashing $prefix_{H7}$ together
  with $R \parallel pk \parallel m$ via $HashToScalar$, rather than hashing $R \parallel pk \parallel m$ alone with
  the ciphersuite's plain hash. Without the prefix, the COCKTAIL Proof of Possession challenge $H(R \parallel pk
  \parallel m)$ would be byte-identical to an EdDSA challenge over the same inputs, and an off-the-shelf EdDSA
  verifier would accept the signature. Implementations **MUST** include $prefix_{H7}$ as the first bytes of the
  challenge input (or, for secp256k1, use the BIP-340 tagged-hash construction defined above).
- **Deterministic nonce**: The nonce $k$ is derived deterministically from $sk$ and $m$ via a tagged prefix, which
  prevents nonce-reuse attacks across distinct messages.
- **Fault-injection caveat**: Pure deterministic nonces are vulnerable to fault-injection adversaries who can induce
  two signatures over the same message with different internal state. Implementations operating in environments where
  physical fault injection is plausible **SHOULD** mix in fresh randomness (e.g., feed an additional 32-byte random
  string into the nonce hash input).
- **Public-key binding**: The challenge includes $R$, $pk$, and the full message $m$, binding the signature to all
  inputs.
- **Not RFC-compatible**: This signature scheme is NOT the same as EdDSA (RFC 8032), ECDSA, or BIP-340.
  Implementations **MUST** use the scheme specified here to ensure interoperability with COCKTAIL-DKG.

## Security Considerations

- **Coordinator Role**: The coordinator is **not trusted for any security property**. The protocol relies on the
  coordinator only for **liveness** (i.e., for messages to make forward progress through the rounds) and even
  this is a best-effort assumption: a misbehaving coordinator can degrade availability (by refusing to broadcast)
  or attempt a split-view attack (by sending different messages to different participants), but neither breaks
  any cryptographic property of the protocol. A malicious coordinator cannot learn participants' secret shares or
  the final group secret key (confidentiality), cannot forge a successful protocol run (soundness), and cannot
  cause honest participants to accept divergent outputs (consistency): the CertEq phase in Round 3 detects any
  split-view, and recovery procedures bind to the agreed-upon transcript. Implementers **MUST NOT** treat the
  coordinator as having any privileged role beyond message routing.
- **Proof of Possession (PoP)**: The PoP in Round 1 prevents a malicious participant from performing a rogue key attack.
  By signing their commitment $C_{i,0}$ with the corresponding secret $a_{i,0}$, each participant proves they actually
  know the secret key they are contributing. Without this, an attacker could contribute a public key for which they
  don't know the private key, leading to an unusable group key. The PoP message includes the context string (which
  cryptographically binds the ordered participant set $(P_1, \ldots, P_n)$ per the Setup MUSTs), the full VSS
  commitment $C_i$, and the ephemeral key $E_i$. The participant index $i$ is not explicitly included in the PoP
  message because it is implicitly bound through the context string (which binds all $P_j$ in order) and through
  the position of the message in the broadcast.
- **Verifiable Secret Sharing (VSS)**: Feldman's VSS scheme ensures that even if a participant is malicious and sends
  incorrect shares, they will be caught. The VSS verification check in Round 2 (step 3.4) allows each participant to
  verify that the share they received is consistent with the public commitment. This prevents a malicious participant
  from corrupting the final key.
  - Participant IDs ($i$, $j$, etc.) **MUST NOT** be equal to 0 or a multiple of the elliptic curve group order.
    Respecting this requirement prevents a [zero share attack](https://www.zkdocs.com/docs/zkdocs/protocol-primitives/verifiable-secret-sharing/).
- **Encryption of Shares**: The use of an AEAD to encrypt the secret shares $s_{i,j}$ is crucial. It provides
  confidentiality against an eavesdropper on the communication channel and authenticity to prevent a man-in-the-middle
  from tampering with the shares. The encryption key is derived using two ECDH shared secrets: one from the sender's
  ephemeral key with the recipient's static key ($S^{(e)}_{i,j} = e_i * P_j$), and one from the sender's static key
  with the recipient's static key ($S^{(d)}_{i,j} = d_i * P_j$). This approach provides:
  - **Limited post-compromise protection**: The ephemeral component prevents compromise of the sender's long-term
    static key alone from decrypting past ciphertexts after the sender erases $e_i$. This is not full forward secrecy:
    compromise of a recipient's static key $d_j$, together with the transcript and archived ciphertexts, allows recovery
    of that recipient's historical shares.
  - **Operational blame-finding**: If decryption fails, the recipient can identify which sender's ciphertext failed
    locally. This failure is not publicly verifiable from public keys alone. Public dispute resolution requires
    selecting one of the options enumerated in
    [Differences from ChillDKG](#5-ciphertexts-not-bound-by-the-transcript): Options 1 and 2 provide only
    ciphertext binding (which ciphertext was sent), while Option 3 provides public verification of the decryption
    outcome itself.
  - **Sender authentication**: The inclusion of the static-to-static ECDH binds the ciphertext to the sender's identity,
    preventing an attacker from replaying or modifying ciphertexts without detection.
- **Cofactor Security**: As noted in the [working with curves with small subgroups](#working-with-curves-with-small-subgroups)
  section, curves like Ed25519 and Ed448 have small cofactors. It is critical that implementations use prime-order group
  abstractions where available, or enforce explicit prime-order subgroup validation on every decoded point, to prevent
  small subgroup attacks where an attacker could submit a low-order point to leak information.
- **Participant Authentication**: Throughout the protocol, participants are authenticated to each other via their
  long-term static key pairs. The pairwise ECDH key agreement used to encrypt shares in Round 1 provides deniable
  authentication; only the owner of the corresponding static private key can derive the correct symmetric key to decrypt
  and verify the secret share. This ensures that participants are communicating with the intended parties. The final
  signature on the transcript in Round 3 provides explicit, non-repudiable authentication of each participant's agreement
  on the final public state.
- **Transcript Certification**: The final round where all participants sign the public transcript is vital. It ensures
  that all honest participants have a consistent view of the entire public state of the DKG. If a malicious coordinator
  tried to give different participants different sets of messages, the transcript signatures would not match, and the
  protocol would fail safely. This provides a guarantee of explicit consensus. Notably, COCKTAIL-DKG does not require
  an honest majority for security: even a single honest participant will detect a split-view attack. The success
  certificate (transcript plus all signatures) serves as cryptographic proof that all participants agreed on the same
  public state at protocol completion.

### Working with curves with small subgroups

Certain elliptic curves used in cryptography are in the so-called Montgomery or Edwards model, picked for particularly
efficient arithmetic. The downside to these curves is that they have an order which factors as $n = [h] * q$ for some
small value $h$ and large prime $q$. If an attacker can select a point $P$ of order $h$ they can potentially leak
partial information about the secret scalars from the output of $[s] P$. (They specifically learn $s \bmod h$).

Curves in these families we consider include ed25519 with $h = 8$, edwards448 with $h = 4$, and JubJub with $h = 8$.
For Ed25519, COCKTAIL-DKG uses Ristretto255 internally and emits Ed25519 outputs via a canonical lift. For Ed448,
COCKTAIL-DKG emits raw RFC 9591-compatible Ed448 outputs, but implementations may still use Decaf448 internally as
an implementation strategy as long as they apply the specified Decaf448-to-Ed448 output mapping and enforce the same
prime-order input validation. In all cases, decoded protocol points on cofactor-bearing curves **MUST** be rejected
unless they are valid, non-identity, prime-order subgroup points.

The "cofactor clearing then check for identity" shortcut ($[h] \cdot P \stackrel{?}{=} O$) tests only that $P$ is
not a small-subgroup point and does **NOT** establish prime-order subgroup membership for mixed-order points. It
**MUST NOT** be used as a substitute for explicit subgroup-membership checks. Separately, cofactor clearing on input
does not define a canonical raw-curve output representative; any ciphersuite that uses an internal prime-order
abstraction but emits raw curve encodings must specify its output lift explicitly, as COCKTAIL-DKG does for Ed25519
and Ed448.

JubJub does not have an analogous prime-order group abstraction in widespread use. For COCKTAIL-DKG implementations
using the JubJub ciphersuite, validating that a decoded byte string represents a valid curve point is **not**
sufficient. All decoded protocol points (static public keys $P_i$, ephemeral public keys $E_i$, VSS commitment points
$C_{i,k}$, and Schnorr commitment points $R$) **MUST** be verified to lie in the prime-order subgroup of order $q$
by an explicit subgroup-membership check: compute $[q] \cdot P$ and abort if the result is not the identity element.
The "cofactor clearing then check for identity" alternative ($[h] \cdot P \stackrel{?}{=} O$) tests only that $P$ is
not a small-subgroup point and does **NOT** establish prime-order subgroup membership for mixed-order points; it
**MUST NOT** be used as a substitute for the explicit subgroup-membership check. Raw cofactor-8 JubJub points that
fail the subgroup check **MUST NOT** be accepted as protocol points.

COCKTAIL-DKG handles abstractions and underlying raw curves on a per-ciphersuite basis:

- **COCKTAIL(Ristretto255, SHA-512)**: operates entirely within the Ristretto255 abstraction and emits Ristretto255
  outputs. No lift to raw Ed25519 is performed.
- **COCKTAIL(Ed25519, SHA-512)**: operates over Ristretto255 internally (for cofactor safety), but emits Ed25519
  outputs. The cross-abstraction lift at output time is performed by the deterministic three-step output mapping 
  defined in the [COCKTAIL(Ed25519, SHA-512) ciphersuite definition](#ciphersuite-definitions); namely, encode the
  Ristretto255 element per [RFC 9496 §4.3.2](https://www.rfc-editor.org/rfc/rfc9496.html#section-4.3.2),
  decode it per [RFC 9496 §4.3.1](https://www.rfc-editor.org/rfc/rfc9496.html#section-4.3.1) to obtain the
  canonical Edwards point in the prime-order subgroup, and encode that Edwards point per RFC 8032.
  
  The generic cofactor-clearing identity discussed in this section is **not** part of that mapping and **MUST NOT** 
  be used to emit Ed25519 outputs; the [RFC 9496 §4.3.1](https://www.rfc-editor.org/rfc/rfc9496.html#section-4.3.1)
  procedure already returns a prime-order-subgroup point, so the cofactor-clearing step is redundant and would also
  fail to pin down the canonical Edwards representative (different implementations would emit different bytes for 
  the same Ristretto255 element).

  Secret shares $x_i$ are scalars in $[0, q-1]$ and are emitted in the Ed25519 scalar encoding without
  further transformation.
- **COCKTAIL(Ed448, SHAKE256)**: may operate over Decaf448 internally (for cofactor safety), but emits Ed448
  outputs. The cross-abstraction lift at output time is performed by the deterministic output mapping defined in
  the [COCKTAIL(Ed448, SHAKE256) ciphersuite definition](#ciphersuite-definitions): encode the Decaf448 element
  per [RFC 9496 §5.3.2](https://www.rfc-editor.org/rfc/rfc9496.html#section-5.3.2), decode it per 
  [RFC 9496 §5.3.1](https://www.rfc-editor.org/rfc/rfc9496.html#section-5.3.1) to obtain a canonical Edwards448
  representative, project that representative into the prime-order subgroup as 
  $P' = [4^{-1} \bmod q] \cdot ([4] \cdot P)$, and encode $P'$ per [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html).
  Raw-Edwards implementations instead perform explicit subgroup checks on every decoded point and encode
  outputs directly.
- For all ciphersuites, the H6 and H7/nonce prefixes are ciphersuite-specific (e.g.,
  `COCKTAIL-DKG-Ed25519-SHA512-H6` vs `COCKTAIL-DKG-Ristretto255-SHA512-H6`), so the Schnorr signatures, AEAD
  encryption keys, and transcripts produced by COCKTAIL(Ed25519) and COCKTAIL(Ristretto255) are domain-separated
  even though their internal arithmetic operates over the same prime-order group.

Implementations that need to interoperate with separate protocols using raw curves not covered by the lift rules
above **MUST** treat any such cross-abstraction lift as out-of-band and specify the canonical-representative
selection there; cofactor clearing alone is not sufficient when the raw curve is not directly addressed by this
document.

### Optional Application Payloads

COCKTAIL-DKG supports an optional application-defined payload that can be included alongside each secret share in the
encrypted ciphertext. This feature enables applications to derive additional shared secrets during the DKG without
running a separate protocol.

**Use Cases:**

- **Backup encryption keys**: Participants can exchange random contributions to derive a shared backup key.
- **Session keys**: Applications can establish pairwise or group session keys for subsequent communication.
- **Application-specific data**: Any data that needs to be securely exchanged between participants during key generation.

**Payload Format:**

The plaintext encrypted in each ciphertext $c_{i,j}$ has the format:
$plaintext_{i,j} = s_{i,j} \parallel payload_{i,j}$

Where $s_{i,j}$ is the fixed-size secret share (determined by the scalar size of the ciphersuite) and $payload_{i,j}$
is the variable-length application payload (which may be empty).

**Payload Commitments:**

If applications use payloads and need to ensure all participants agree on the payloads exchanged, they **SHOULD**
include commitments to the payloads in the transcript or in application-specific extension data. A recommended
commitment format is:
$commitment = H(len(payload) \parallel payload)$

Where $len(payload)$ is the length of the payload encoded as a little-endian 64-bit integer. This format ensures
domain separation between payloads of different lengths.

**Security Note:**

The optional payload is encrypted and authenticated by the same AEAD that protects the secret share. However, the
payload is NOT verified against the VSS commitments (only the share portion is). Applications using payloads **MUST**
implement their own verification logic if payload integrity beyond AEAD authentication is required.

### Differences from ChillDKG

COCKTAIL-DKG is derived from [ChillDKG](https://github.com/BlockstreamResearch/bip-frost-dkg) but introduces several
important changes that break backwards compatibility:

#### 1. Key Derivation Uses Both Static and Ephemeral ECDH

ChillDKG derives encryption keys using only an ephemeral-to-static ECDH:

$S_{i,j} = e_i * P_j$

COCKTAIL-DKG uses both ephemeral-to-static AND static-to-static ECDH:

$S^{(e)}_{i,j} = e_i * P_j$ and $S^{(d)}_{i,j} = d_i * P_j$

**Why this matters:**

Including the sender's static key in the derivation binds each ciphertext to the sender and recipient identities, in
addition to the sender's ephemeral key. This prevents ciphertexts from being replayed across senders, recipients, or
sessions with the same ephemeral public key and context.

This change does not make decryption-failure blame publicly verifiable by itself. A third party cannot compute or
verify Diffie-Hellman shared secrets from public keys alone without an additional proof mechanism. The full set
of options for an application that needs public resolution of decryption disputes is documented in
[Differences from ChillDKG](#5-ciphertexts-not-bound-by-the-transcript) and is divided there into two
sub-properties (ciphertext binding vs public decryption verification); the static-static ECDH binding introduced
in this section only prevents *ciphertext replay* across senders/recipients/sessions, which is a complementary
property to either binding or decryption verification.

#### 2. Extended H6 Function

The H6 key derivation function now includes the sender's static public key $P_s$ in addition to the recipient's
public key $P_r$: $H6(x, E, P_s, P_r, extra)$ instead of $H6(x, E, P_r, extra)$.

#### 3. Optional Application Payloads

COCKTAIL-DKG allows optional application-defined data to be included in the encrypted share ciphertexts, which
ChillDKG does not support.

#### 4. Multi-Ciphersuite Scope (No Taproot Tweak)

ChillDKG is specified only over secp256k1 and additionally specifies a Taproot-safe BIP-341 key tweak that ensures
the resulting group public key $Y$ is safe to use as a Bitcoin Taproot output (preventing a malicious participant
from embedding a hidden Taproot script-path commitment).

COCKTAIL-DKG covers seven ciphersuites (most of which are not cryptocurrency-specific and therefore have no Taproot
analogue) and therefore **does not specify a built-in Taproot tweak**. 

Applications using COCKTAIL(secp256k1, SHA-256) as the input to a Bitcoin Taproot deployment **MUST** apply the
externally-applied mitigation defined in the [Bitcoin Taproot Warning in the COCKTAIL(secp256k1, SHA-256) ciphersuite definition](#ciphersuite-definitions);
that warning is the single normative source for the mitigation requirement.

#### 5. Ciphertexts Not Bound by the Transcript

ChillDKG's CertEq transcript binds all participants' encrypted shares so that the success certificate cryptographically
attests to the exact ciphertexts each participant received, which in turn makes decryption failure blame publicly
verifiable from the certificate alone.

COCKTAIL-DKG's CertEq transcript binds only the ciphersuite identifier, context, parameters, static public keys, VSS
commitments, PoPs, ephemeral public keys, and application-specific extension; but **not** the ciphertexts. This is a
deliberate trade-off in favour of a smaller, simpler transcript and a smaller success certificate. The cost is that
decryption failures are not publicly verifiable from the certificate alone, because the AEAD verification key 
$k_{j,i}$ is derived from recipient $i$'s static private key $d_i$ and is therefore not public.

Decryption-failure attribution has two distinct sub-properties:

- **Ciphertext binding:** publicly establishing *which* ciphertext bytes sender $j$ actually addressed to recipient $i$,
  so that the ciphertext under dispute is unambiguous and non-repudiable.
- **Public decryption verification:** publicly establishing *whether* that ciphertext does or does not decrypt to a
  valid share under the key derived from $(d_i, E_j, P_j, P_i, context)$; note $E_j$ (public ephemeral key), not $e_j$
  (the sender's ephemeral private key, which the recipient does not have).

The options below split along this axis. Applications that need ciphertext binding only (i.e., that are willing to trust
the recipient's self-attested decryption outcome once the ciphertext is binding) **MUST** select option 1 or option 2.
Applications that additionally need independent public verification of the decryption outcome itself **MUST** combine 
option 3 with option 1 or option 2. Option 3 is not, by itself, sufficient because it proves the decryption outcome for 
*some* claimed ciphertext but does not pin down *which* ciphertext sender $j$ actually addressed to recipient $i$. 

Note that "fully-non-interactive certificate-only" adjudication (i.e., adjudication using only the signed success 
certificate, with no additional out-of-band material) is only achievable via the combination option 1 + option 3;
option 2 + option 3 also yields third-party-verifiable blame, but requires an out-of-band republished $msg_{1|j}$
and its application-layer authentication material in addition to the certificate.

The three options also differ in *when* they apply. Option 1 binds ciphertexts via the success certificate, so it is 
only available **after** a successful DKG run (e.g., for recovery-time disputes when an archived ciphertext fails 
decryption). Options 2 and 3 are usable both during an active session (a Round 2 abort where no success certificate
exists yet) and after a successful run; for active-session disputes, option 1 is not available and applications **MUST**
rely on option 2, option 3, or some application-level transport authentication described separately.

1. **Commit to ciphertexts via the application-specific extension** *(ciphertext binding only; success-path disputes
   only).* Place a binding commitment to all $msg_{1|j}$ ciphertexts (e.g., a hash of the participant-ordered
   concatenation of the framed ciphertexts) in the application-specific extension bytes that feed the transcript.
   The success certificate then binds the ciphertexts via the signed transcript; an after-the-fact dispute can reference
   the certificate to fix the ciphertext under dispute. This requires the DKG to have completed successfully 
   (a certificate to exist) and does **not** by itself let a third party verify the decryption outcome; for that,
   combine with option 3 or accept the recipient's self-attestation.
2. **Preserve the original Round 1 messages out-of-band** *(ciphertext binding only; requires an application-level
   transport-authentication layer).* Each participant durably stores their own $msg_{1|j}$ outside the protocol's
   required artifacts. A framed participant can later republish their original message. **The COCKTAIL-DKG PoP signs
   only `context || C_j || E_j` and does NOT sign the ciphertexts**, so the bare republished $msg_{1|j}$ plus the
   transcript's public material is *insufficient* to bind the ciphertexts to sender $j$: a third party cannot
   distinguish the original ciphertexts from substituted ones on PoP/transcript evidence alone.
   
   To make option 2 sound, the application **MUST** layer some independent authentication over the $msg_{1|j}$ bytes.
    - For example, a sender-signed transport envelope that signs the full message (including ciphertexts), a
      per-participant signature over the framed ciphertext bundle, or a broadcast layer whose receipts are bound to
      specific bytes.
   With such a layer in place, this establishes which ciphertext was sent; without it, option 2 is not sufficient.
3. **Define a separate dispute-evidence channel** *(public decryption-outcome verification; ciphertext binding must come
   from Option 1 or Option 2).* Define an application-level mechanism that produces a non-interactive proof that
   recipient $i$'s claimed Round 2 decryption outcome for $c_{j,i}$ is correct.
   
   This option attests only to the **decryption outcome**; it does not by itself attest to which ciphertext bytes were
   originally sent. Option 3 therefore **MUST** be combined with Option 1 or Option 2 to produce a complete,
   third-party-verifiable decryption-failure blame chain (Option 1/2 fixes the disputed ciphertext bytes; Option 3
   proves what happens when those bytes are AEAD-processed under the recipient's private key). Option 3 is scoped
   specifically to Round 2 **decryption-related** aborts (AEAD failure, non-canonical plaintext, VSS mismatch).
   
   The remaining Round 2 abort conditions fall into two buckets:

   - **Transcript-verifiable aborts**: invalid commitment length and invalid PoP. Both $C_j$ and $PoP_j$ are part of the
     transcript and are therefore bound by the CertEq signatures (when a transcript exists) or directly observable from
     the broadcast (during an active session); a third party can independently check $|C_j| \neq t$ or that $PoP_j$ does
     not verify against $C_{j,0}$ over $context \parallel C_j \parallel E_j$, using only public data. These aborts do
     not require Option 3.
   - **Ciphertext-dependent aborts**: framing-format failures (a malformed length prefix on a framed ciphertext) and the
     decryption-related aborts covered by Option 3. Because the ciphertexts themselves are not bound by the transcript,
     these aborts are **not** publicly verifiable from the transcript and Round 1 messages alone; public blame for
     either kind requires Option 1 (extension commitment) or Option 2 (out-of-band republication with application-level
     authentication) to first establish which ciphertext bytes are under dispute. With ciphertext bytes thereby fixed,
     a framing-format failure is locally checkable by any third party from the bytes themselves; a decryption-related
     failure additionally requires Option 3 for public verification of the decryption outcome.

   The Round 2 final self-consistency check ($x_i \cdot B \neq Y_i$) is mathematically guaranteed to pass when the VSS
   share verification has passed. So it is a defense-in-depth check against implementation bugs rather than a
   public-blame scenario, and is therefore not addressed by any of the three options above.

   The proof system is application-defined, but the public statement it **MUST** establish is precisely as follows:

   - **Public inputs** (visible to the verifier): the ciphersuite identifier; the framed ciphertext
     $\widetilde{c_{j,i}}$ that is the subject of the dispute; the sender's ephemeral public key $E_j$; the sender's
     static public key $P_j$; the recipient's static public key $P_i$; the recipient's participant index $i$; the
     sender's full VSS commitment $C_j = (C_{j,0}, \ldots, C_{j,t-1})$; the session `context`; and a tag identifying
     which of the three Round 2 decryption-related failure modes is being proved (`AEAD-fail` /
     `non-canonical-plaintext` / `VSS-mismatch`).

     The sender index $j$, the recipient index $i$, the framed ciphertext $\widetilde{c_{j,i}}$, and the failure-mode
     tag are **never** recoverable from $T$ alone (they identify *what* is being disputed), so they **MUST** always
     appear as explicit public inputs. When the proof is additionally bound to a published success certificate signed
     under transcript $T$, the remaining inputs ($E_j$, $P_j$, $C_j$ from $T$ at the j-th positions in the ordered
     participant lists; $P_i$ from $T$ at the i-th position; and `context` from the ciphersuite_id-prefixed `context`
     field at the head of $T$) are recoverable from $(T, j, i)$ and the proof **MAY** take
     $(T, j, i, \widetilde{c_{j,i}}, \text{tag})$ as a more compact public input and require the verifier to extract
     those values from $T$ before evaluating the relation.
   - **Private witness** (held by the recipient): the recipient's static private key $d_i$.
   - **Relation proved**: the witness $d_i$ satisfies $d_i \cdot B = P_i$ (witness-binding to the named recipient key;
     without this, an arbitrary scalar could produce a fake AEAD outcome for some other recipient's key), **and**
     deriving $S^{(e)}_{j,i} = d_i \cdot E_j$ and $S^{(d)}_{j,i} = d_i \cdot P_j$, encoding them per
     [ECDH Shared-Secret Encoding](#ecdh-shared-secret-encoding), and computing the AEAD key and nonce via
     $H6(\cdot)$ with the ciphersuite's $prefix_{H6}$, $E_j$, $P_j$, $P_i$, and `context`, produces an AEAD outcome on
     the inner $c_{j,i}$ consistent with the claimed failure-mode tag:
     - **AEAD-fail tag**: AEAD authentication of $c_{j,i}$ fails.
     - **Non-canonical-plaintext tag**: AEAD authentication succeeds, but the recovered plaintext is shorter than the
       ciphersuite's scalar encoding size, **or** its leading scalar-sized portion does not decode to a canonical scalar
       in $[0, q-1]$ per [Primitive Types](#primitive-types).
     - **VSS-mismatch tag**: AEAD authentication succeeds, the leading portion decodes to a canonical scalar $s$, and
       $s \cdot B \neq \sum_{k=0}^{t-1} i^k \cdot C_{j,k}$.

   These three tags correspond exactly to the three Round 2 abort conditions for decryption-related
   failures, so any honest Round 2 decryption-failure abort can be backed by a proof under this option. The
   verifier learns the failure-mode tag and the identity of the framed ciphertext, but learns **no
   information about $d_i$** beyond what is already implied by $P_i$. The specific zero-knowledge proof
   system (e.g., a Bulletproofs- or PLONK-style circuit over AEAD verification, or a sigma-protocol-based
   DH+AEAD proof) is out of scope for this document; any sound, zero-knowledge, non-interactive argument for
   the statement above is sufficient.

   When combined with Option 1 (extension commitment binds $\widetilde{c_{j,i}}$ via the success
   certificate) or Option 2 (republished original $msg_{1|j}$ supplies $\widetilde{c_{j,i}}$ from an
   application-authenticated binding source), Option 3 produces complete, third-party-verifiable
   decryption-failure blame without requiring further participant cooperation. The combined evidence is
   *certificate-only* only when paired with Option 1, because Option 1 binds the disputed ciphertext via the
   signed transcript itself; the Option 2 + Option 3 combination produces blame that is third-party-verifiable
   but **not** certificate-only; it additionally requires the out-of-band $msg_{1|j}$ and its application-
   layer authentication material to be made available to the verifier. Option 3 alone, without 1 or 2, proves
   the decryption outcome for *some* claimed ciphertext but does not bind the disputed ciphertext to a
   particular sender's Round 1 message and is therefore insufficient on its own for end-to-end public blame.

#### 6. Recovery Requires Both Common Data and a Per-Participant Encrypted Share Bundle

In ChillDKG, recovery is possible from the participant's static secret key plus the common recovery data
(transcript and certificate) alone.

In COCKTAIL-DKG, recovery additionally requires a per-participant **encrypted share bundle** $C^{rec}_i$ 
(the ordered, length-framed Round 1 ciphertexts addressed to the recovering participant). See
[Backup Requirements](#backup-requirements) for the full backup set.

### Share Recovery

COCKTAIL-DKG inherits a key feature from ChillDKG: the ability to recover DKG outputs from minimal backup material.
This eliminates the need for participants to store session-specific secrets and simplifies backup procedures.

#### Recovery Data

The **common recovery data** for a successful DKG session consists of:

1. **Transcript ($T$):** The canonical byte representation of the protocol transcript, as constructed in Round 3.
2. **Success Certificate:** The collection of all $n$ signatures on the transcript: $sig_1, sig_2, \ldots, sig_n$.

This common recovery data is identical for all participants and contains no confidential information. It can be safely:

- Stored with untrusted backup providers
- Obtained from any cooperative participant or the coordinator
- Shared publicly without compromising security

Recovering participant $i$ additionally needs their **participant-specific encrypted share bundle**:

```math
C^{rec}_i = \widetilde{c_{1,i}} \parallel \widetilde{c_{2,i}} \parallel \cdots \parallel \widetilde{c_{n,i}}
```

where each $\widetilde{c_{j,i}}$ is the length-prefixed framed Round 1 ciphertext from participant $j$ to
participant $i$ (length encoded as a 64-bit big-endian unsigned integer, as defined under $msg_{1|i}$ above), in
participant order. This bundle is not identical for all participants. The bundle is encrypted, but implementations
should treat it as sensitive backup material because compromise of $d_i$ plus $C^{rec}_i$ allows decryption of
participant $i$'s historical shares.

#### Backup Requirements

A complete backup for any participant $i$ consists of three components:

1. **Static Secret Key ($d_i$):** The participant's long-term static private key.
2. **Common Recovery Data:** The transcript and success certificate from each DKG session the participant joined.
3. **Encrypted Share Bundle ($C^{rec}_i$):** The ordered, length-framed ciphertexts
   $\widetilde{c_{1,i}}, \ldots, \widetilde{c_{n,i}}$ (each prefixed with its 64-bit big-endian length, as defined
   in [Protocol Messages](#protocol-messages) under $msg_{1|i}$) for each DKG session.

If an application does not store $C^{rec}_i$ directly in the participant's backup, it **MUST** ensure the exact
ciphertexts can be retrieved later from durable coordinator or application storage. Recovery is impossible if the
participant loses both their local encrypted share bundle and every durable copy of those ciphertexts.

This is a significant simplification compared to traditional DKG backup schemes, which typically require storing
session-specific secrets for each key generation ceremony.

#### Recovery Algorithm

Given the static secret key $d_i$, the common recovery data, and the participant-specific encrypted share bundle, a
participant can deterministically reconstruct all DKG outputs:

**Input:**

- $d_i$: The participant's static secret key.
- $T$: The transcript from a successful DKG session.
- $\{sig_1, \ldots, sig_n\}$: The success certificate.
- $C^{rec}_i = \widetilde{c_{1,i}} \parallel \ldots \parallel \widetilde{c_{n,i}}$: The ordered, length-framed Round 1
  ciphertexts sent to participant $i$ (each framed with a 64-bit big-endian length prefix).

**Output:**

- $x_i$: The participant's secret share.
- $Y$: The group public key.
- $Y_1, \ldots, Y_n$: The public verification shares.

**Steps:**

1. **Extract Parameters:** Parse the transcript to obtain:
   - The ciphersuite identifier string. Implementations **MUST** verify that the ciphersuite identifier matches the one
     expected by the recovery routine; mismatch indicates the wrong recovery codepath and **MUST** abort. This step
     occurs before signature verification because the signature scheme (Schnorr `Verify`, `HashToScalar`, point/scalar
     encodings, etc.) is ciphersuite-dependent.
   - The context string and its length
   - The number of participants $n$ and threshold $t$
   - All static public keys $P_1, \ldots, P_n$
   - All VSS commitments $C_1, \ldots, C_n$
   - All Proofs of Possession $PoP_1, \ldots, PoP_n$
   - All ephemeral public keys $E_1, \ldots, E_n$
   - The application-specific extension (if any)
2. **Validate Certificate:** Using the ciphersuite parsed above, verify each signature $sig_j$ on the transcript
   $T$ against the public key $P_j$ extracted from the transcript using the Schnorr `Verify` algorithm. If any
   signature is invalid, abort with an error.
3. **Determine Participant Index:** Find the unique index $i$ such that $P_i = d_i * B$. If zero or more than one
   matching index exists, abort.
4. **Reconstruct Encryption Keys:** For each participant $j$ from $1$ to $n$:
   1. Compute the ECDH shared secrets:
      - $S^{(e)}_{j,i} = d_i * E_j$ (using the sender's ephemeral key)
      - $S^{(d)}_{j,i} = d_i * P_j$ (using the sender's static key)
   2. Derive the symmetric key $k_{j,i}$ and nonce $iv_{j,i}$ using H6, with the same sender/recipient ordering used
      in Round 2.
5. **Load Ciphertexts:** Parse $C^{rec}_i$ as the concatenation of exactly $n$ length-framed ciphertexts: for each $j$
   from 1 to $n$, read the next 8 bytes as a 64-bit big-endian unsigned integer $L_j$, then read the next $L_j$ bytes as
   the AEAD ciphertext $c_{j,i}$. Abort if any of the following hold: the bundle terminates before all $n$ ciphertexts
   are recovered; any $L_j$ exceeds the implementation's maximum-ciphertext-size policy; any $c_{j,i}$ is shorter than
   the ciphersuite's minimum ciphertext size (scalar encoding size plus AEAD authentication tag size); or there are any
   bytes remaining in $C^{rec}_i$ after the $n$th framed ciphertext has been read. The recovery bundle **MUST** parse
   exactly, with no trailing data.
6. **Decrypt and Verify Shares:** For each participant $j$, decrypt $c_{j,i}$ using $k_{j,i}$ and $iv_{j,i}$ to obtain
   $plaintext_{j,i}$. If AEAD decryption fails, abort. If $plaintext_{j,i}$ is shorter than the ciphersuite's scalar
   encoding size, or if the leading scalar-sized portion does not decode to a canonical scalar in $[0, q-1]$, abort.
   Set $s_{j,i}$ to the decoded leading scalar. Verify each share against the VSS commitment:
   $s_{j,i} * B = \sum_{k=0}^{t-1} i^k \cdot C_{j,k}$.
   If the equation does not hold for any $j$, the recovery procedure **MUST** abort with an error. Successful recovery
   requires every share to verify against the transcript-bound VSS commitment, mirroring the Round 2 share-verification
   MUST.
7. **Compute Final Share:** $x_i = \sum_{j=1}^{n} s_{j,i}$.
8. **Compute Public Outputs:**
   - Group public key: $Y = \sum_{j=1}^{n} C_{j,0}$.
   - Public verification shares: For each participant $m$, $Y_m = \sum_{j=1}^{n} \sum_{k=0}^{t-1} m^k \cdot C_{j,k}$.

#### Privacy Considerations

Users should be aware that common recovery data reveals:

- Session parameters (threshold $t$ and number of participants $n$)
- All participants' static public keys ($P_1, \ldots, P_n$)
- The group public key ($Y$) and public verification shares
- The application-specific extension (if used)

The participant-specific encrypted share bundle additionally reveals ciphertext sizes, and ciphertext sizes may reveal
application payload sizes. If the participant's static secret key is later compromised, the encrypted share bundle can
be decrypted to recover that participant's historical shares and any encrypted payloads.

This information may create correlations between participants and their threshold setup. For privacy-sensitive
applications, the recovery material **SHOULD** be encrypted before storage with untrusted providers. A recommended
approach is to derive an encryption key from the static secret key using the ciphersuite's hash function:

$$k_{backup} = H(\text{"COCKTAIL-BACKUP-KEY"} \parallel d_i)$$

#### Security Considerations for Recovery

1. **Timing of Critical Key Use:** Participants **MUST NOT** rely on the group public key $Y$ for **critical
   operations** (operations whose loss-of-access consequences are catastrophic; e.g., long-lived asset custody,
   irreversible signatures, anchored production deployments) until they have confirmed that all participants
   possess the common recovery data and their own participant-specific encrypted share bundles. A catastrophic
   scenario could otherwise occur: one participant deems the session successful and begins using the threshold
   key for critical operations, but they are the only one with complete recovery material. If that participant's
   storage fails, the key becomes unrecoverable and any data or operations depending on it are lost. Non-critical
   use (e.g., low-stakes test signatures, internal protocol-correctness exchanges, or short-lived ceremonies that
   can be replayed) is allowed before confirmation; see item 3.

2. **Explicit Confirmations:** Before using a threshold public key for critical operations, applications
   **SHOULD** obtain explicit confirmations from all participants that they have successfully stored the common
   recovery data and their own encrypted share bundles.

3. **Recovery Without Confirmations:** If a participant receives complete recovery material after a session but
   cannot verify other participants' completion, they **MAY** still recover their outputs for non-critical future
   signing participation. However, they **MUST NOT** rely on that threshold key for critical operations until all
   participants have confirmed storage.

## Alternatives

- **Trusted Dealer**: Simpler but introduces a single point of failure. COCKTAIL-DKG is for scenarios where a trusted
  dealer is unavailable or undesirable.
- **Original FROST DKG**: Requires pre-established secure channels between all participant pairs. COCKTAIL-DKG builds
  in its own encryption layer (EncPedPop), making it usable over insecure channels.

## Appendix A: Pseudocode

This appendix provides a series of algorithms that describe the COCKTAIL-DKG protocol in a high-level,
implementation-agnostic manner. The notation is meant to be illustrative rather than strictly formal.

> [!NOTE]
> **Implementation note:** All scalar arithmetic in the pseudocode below (polynomial evaluation, share summation,
> index powers, etc.) is performed in $\mathbb{F}_q$. The pseudocode does not always show explicit `mod q` for
> brevity; implementations using arbitrary-precision integer types **MUST** reduce modulo $q$ before encoding any
> scalar to bytes, per the Scalar primitive type definition.

### Algorithm 1: Polynomial Generation and VSS Commitment

**Input:**

- `t`: The threshold parameter.
- `G`: The generator point of the elliptic curve group.
- `q`: The order of the elliptic curve group.

**Output:**

- `f`: A secret polynomial of degree `t-1`.
- `C`: A vector of public commitments to the polynomial coefficients.

**Steps:**

1. Initialize an empty polynomial f.
2. Initialize an empty list of commitments C.
3. For k from 0 to t-1:
    1. Generate a random scalar a_k in the range [0, q-1]. If a_k == 0 (negligible probability), resample.
    2. Add the term a_k * x^k to the polynomial f.
    3. Compute the commitment C_k = a_k * B.
    4. Append C_k to the list C.
4. Return (f, C).

**Pseudocode:**

```python
function GeneratePolynomial(t, G, q):
    f = new Polynomial()
    C = new List<Point>()

    for k from 0 to t-1:
        a_k = RandomScalar(q)
        while a_k == 0:                  # negligible probability; ensures C_k != identity
            a_k = RandomScalar(q)
        f.add_coefficient(a_k)

        C_k = a_k * B
        C.append(C_k)

    return (f, C)
```

---

### Algorithm 2: Secret Share Evaluation

**Input:**

- `f`: A secret polynomial.
- `j`: The index of the recipient participant.

**Output:**

- `s_j`: The secret share for participant `j`.

**Steps:**

1. Evaluate the polynomial f at the point x = j.
2. Let the result be s_j = f(j).
3. Return s_j.

**Pseudocode:**

```python
function EvaluatePolynomial(f, j):
    result = 0
    # iterate from highest degree to lowest
    for a in reverse(f.coefficients):
        result = result * j + a
    return result
```

---

### Algorithm 3: Secret Share Verification

**Input:**

- `s_j`: A secret share received from another participant.
- `j`: The index of the recipient participant (i.e., self).
- `C`: The list of VSS commitments from the sender.
- `G`: The generator point of the elliptic curve group.
- `t`: The threshold parameter.

**Output:**

- `valid`: A boolean indicating if the share is valid.

**Steps:**

1. Compute the public verification point from the share: V = s_j * B.
2. Compute the expected verification point from the commitments:
    1. Initialize an identity point R.
    2. For k from 0 to t-1:
        1. Compute term = (j^k) * C_k.
        2. Add term to R: R = R + term.
3. Compare the points: valid = (V == R).
4. Return valid.

**Pseudocode:**

```python
function VerifyShare(s_ji, i, C_j, G, t):
    # V = s_{j,i} * B
    V = s_ji * B

    # R = sum_{k=0}^{t-1} (i^k * C_{j,k})
    R = IdentityPoint()
    for k from 0 to t-1:
        i_k = power(i, k)
        C_jk = C_j[k]
        term = i_k * C_jk
        R = R + term

    return V == R
```

### Helper: Key and Nonce Derivation

This helper abstracts the ciphersuite-dependent key derivation logic used in Rounds 1 and 2.

```python
function DeriveKeyAndNonce(cs, ecdh_secret, E, P_sender, P_recipient, context):
    if cs.HashFunction.OutputSizeInBytes() >= 56:
        tmp = H6(ecdh_secret, E, P_sender, P_recipient, context)
        return (tmp[0:32], tmp[32:56])
    else:
        ikm = H6(ecdh_secret, E, P_sender, P_recipient, context)
        key = H("COCKTAIL-derive-key" || ikm)
        nonce = H("COCKTAIL-derive-nonce" || ikm)[0:24]
        return (key, nonce)
```

### Algorithm 4: COCKTAIL-DKG Round 1 (Participant `i`)

**Input:**

- `i`: The index of the current participant.
- `t`: The threshold parameter.
- `n`: The total number of participants.
- `cs`: The ciphersuite (providing Group, Hash, AEAD).
- `context`: A session-specific context string.
- `d_i`: The static private key of participant `i`.
- `P_i`: The static public key of participant `i`.
- `P_j`: The static public key of each participant `j` from 1 to `n` (the ordered list `AllPublicKeys` used below
  includes `P_i` at index `i`; the algorithm iterates over all `j` including `j = i`, which produces a self-share).
- `payloads`: (Optional) A map from participant index `j` to application-defined payload bytes.

**Output:**

- `msg1_i`: The Round 1 message to be broadcast.
- `internal_state`: Values to be stored for the next round (e.g., polynomial, ephemeral key).

**Steps:**

1. Generate Polynomial and VSS Commitment:
    1. (f_i, C_i) = Algorithm1(t, cs.Group.G, cs.Group.q)
2. Generate Ephemeral Key:
    1. e_i = cs.Group.RandomScalar(); while e_i == 0: e_i = cs.Group.RandomScalar()    # negligible probability
    2. E_i = e_i * cs.Group.G
3. Compute Proof of Possession (PoP):
    1. Let a_i_0 be the constant term of f_i.
    2. Let C_i_0 be the first commitment in C_i.
    3. PoP_i = Sign(private_key=a_i_0, message=context || C_i || E_i)
       (using the Schnorr scheme; the public key is C_i_0; C_i is encoded as the concatenation of the t compressed
       point encodings, identical to its encoding in msg1_i).
4. Compute and Encrypt Shares:
    1. Initialize an empty list encrypted_shares.
    2. For j from 1 to n:
        1. s_i_j = Algorithm2(f_i, j).
        2. Derive ECDH key using both ephemeral and static secrets. Each scalar-mult result is encoded as a
           ciphersuite-specific fixed-length byte string per [ECDH Shared-Secret Encoding](#ecdh-shared-secret-encoding):
            - ecdh_ephemeral = ecdh_encode(e_i * P_j)
            - ecdh_static = ecdh_encode(d_i * P_j)
            - ecdh_secret = ecdh_ephemeral || ecdh_static
            - If the hash function used has an output size fewer than 56 bytes, use the output of H6 as an Input Keying
              Material to two more hash function calls, which will be used to derive a nonce and key. (Here, H() refers
              to, e.g., sha256):
              - ikm = H6(ecdh_secret, E_i, P_i, P_j, context)
              - key = H("COCKTAIL-derive-key" || ikm)
              - nonce = H("COCKTAIL-derive-nonce" || ikm)\[0:24]
            - If the hash function used has an output size greater than or equal to 56 bytes, just split it:
              - tmp = H6(ecdh_secret, E_i, P_i, P_j, context)
              - key = tmp[0:32] (32 bytes)
              - nonce = tmp[32:56] (24 bytes)
        3. Prepare plaintext with optional payload:
            - payload_i_j = payloads[j] if j in payloads else empty bytes
            - plaintext = s_i_j || payload_i_j
        4. Encrypt plaintext:
            - c_i_j = Encrypt(key, nonce, plaintext)
        5. Wire-frame the ciphertext as `framed_c_i_j = uint64_be(len(c_i_j)) || c_i_j`, then append `framed_c_i_j` to
           `encrypted_shares` (the list stores the on-wire framed bytes, not raw ciphertexts).
5. Construct Message:
    1. msg1_i = (C_i, PoP_i, E_i, encrypted_shares)
6. Store State:
    1. internal_state = (f_i, e_i)
7. Return (msg1_i, internal_state).

**Pseudocode:**

```python
function Round1(i, t, n, cs, context, d_i, P_i, AllPublicKeys, payloads={}):
    (f_i, C_i) = GeneratePolynomial(t, cs.Group.G, cs.Group.q)
    a_i0 = f_i.coefficient(0)
    e_i = cs.Group.RandomScalar()
    while e_i == 0:                       # negligible probability; ensures E_i != identity
        e_i = cs.Group.RandomScalar()
    E_i = e_i * cs.Group.G
    PoP_i = Sign(private_key=a_i0, message=context || C_i || E_i)

    encrypted_shares = new List<FramedCiphertext>()
    for j from 1 to n:
        s_ij = EvaluatePolynomial(f_i, j)
        P_j = AllPublicKeys[j]
        # ecdh_secret = canonical_encode(e_i * P_j) || canonical_encode(d_i * P_j),
        # per "ECDH Shared-Secret Encoding"; each side is a fixed-length byte string for the ciphersuite.
        ecdh_secret = ecdh_encode(cs, e_i * P_j) || ecdh_encode(cs, d_i * P_j)
        (key, nonce) = DeriveKeyAndNonce(cs, ecdh_secret, E_i, P_i, P_j, context)
        payload_ij = payloads.get(j, empty_bytes)
        c_ij = Encrypt(key, nonce, s_ij || payload_ij)
        # Wire-frame with a 64-bit big-endian length prefix; encrypted_shares stores framed bytes.
        framed_c_ij = uint64_be(len(c_ij)) || c_ij
        encrypted_shares.append(framed_c_ij)

    msg1_i = new Round1Message(C_i, PoP_i, E_i, encrypted_shares)
    internal_state = new State(f_i, e_i)
    return (msg1_i, internal_state)
```

### Algorithm 5: COCKTAIL-DKG Round 2 (Participant `i`)

**Input:**

- `i`: The index of the current participant.
- `all_msg1s`: A list of all Round 1 messages from all participants.
- `internal_state`: The state saved from Round 1 (`f_i`, `e_i`).
- `d_i`: The static private key of participant `i`.
- `P_i`: The static public key of participant `i`.
- `AllPublicKeys`: The static public keys of all participants.
- `cs`: The ciphersuite.
- `context`: The session-specific context string.

**Output:**

- `x_i`: The final secret share for participant `i`.
- `Y`: The group public key.
- `Y_i`: The public verification share for participant `i`.
- `received_payloads`: A map from participant index `j` to the received payload bytes (may be empty).
- `transcript_data`: Public data needed for Round 3.

**Steps:**

1. Initialize an empty list received_shares.
2. Initialize an empty map received_payloads.
3. Process messages from each participant j:
    1. For j from 1 to n:
        1. Parse (C_j, PoP_j, E_j, encrypted_shares_j) from msg1_j.
        2. Verify PoP:
            - valid_pop = Verify(public_key=C_j_0, signature=PoP_j, message=context || C_j || E_j)
            - If valid_pop is false, abort and blame participant j.
        3. Decrypt Plaintext:
            - Take $encrypted\_shares\_j[i]$ as the framed ciphertext $\widetilde{c_{j,i}} = uint64\_be(L_{j,i}) \parallel c_{j,i}$.
              Unwrap with bounds checks: if $len(\widetilde{c_{j,i}}) < 8$, or $L_{j,i}$ exceeds the implementation's
              maximum-ciphertext-size policy, or $len(\widetilde{c_{j,i}}) \neq 8 + L_{j,i}$, or
              $L_{j,i} < scalar\_size + AEAD\_TAG\_SIZE$, abort and blame participant $j$. Let $c_{j,i}$ be the
              unwrapped AEAD ciphertext.
            - Let P_j = AllPublicKeys\[j\].
            - Derive ECDH key using both ephemeral and static secrets. Each scalar-mult result is encoded as a
              ciphersuite-specific fixed-length byte string per
              [ECDH Shared-Secret Encoding](#ecdh-shared-secret-encoding):
                - ecdh_ephemeral = ecdh_encode(d_i * E_j)
                - ecdh_static = ecdh_encode(d_i * P_j)
                - ecdh_secret = ecdh_ephemeral || ecdh_static
                - If the hash function used has an output size fewer than 56 bytes, use the output
                  of H6 as an Input Keying Material to two more hash function calls, which will be used
                  to derive a nonce and key. (Here, H() refers to, e.g., sha256):
                  - ikm = H6(ecdh_secret, E_j, P_j, P_i, context)
                  - key = H("COCKTAIL-derive-key" || ikm)
                  - nonce = H("COCKTAIL-derive-nonce" || ikm)\[0:24]
                - If the hash function used has an output size greater than or equal to 56 bytes, just split it:
                  - tmp = H6(ecdh_secret, E_j, P_j, P_i, context)
                  - key = tmp\[0:32\] (32 bytes)
                  - nonce = tmp\[32:56\] (24 bytes)
            - Decrypt:
                - plaintext = Decrypt(key, nonce, ciphertext=c_j_i)
                - If decryption fails, abort and report a decryption failure for participant j's ciphertext.
        4. Parse Plaintext:
            - If `len(plaintext) < scalar_size`, abort and blame participant j.
            - s_j_i = decode_scalar(plaintext\[0:scalar_size\]); if decoding fails (i.e., the bytes do not represent
              a canonical scalar in [0, q-1]), abort and blame participant j.
            - payload_j_i = plaintext\[scalar_size:\] (any remaining bytes are the optional payload)
            - received_payloads\[j\] = payload_j_i
        5. Verify Share:
            - valid_share = Algorithm3(s_j_i, i, C_j, cs.Group.G, t)
            - If valid_share is false, abort and blame participant j.
        6. Add s_j_i to received_shares.
4. Compute Final Keys:
    1. x_i = sum(received_shares) (scalar addition).
    2. Y = sum(C_j_0 for all j) (point addition).
    3. Compute Verification Share Y_i:
        1. Initialize Y_i to the identity point.
        2. For k from 0 to t-1:
            - C_agg_k = sum(C_j_k for all j) (point addition).
            - term = (i^k) * C_agg_k
            - Y_i = Y_i + term
    4. Final Check:
        - If x_i * cs.Group.G != Y_i, abort (protocol failure).
5. Prepare for Round 3:
    1. transcript_data = (cs.id, all_msg1s, context, all_static_public_keys), where cs.id is the ciphersuite
       identifier string (e.g., "COCKTAIL(Ristretto255, SHA-512)").
6. Return (x_i, Y, Y_i, received_payloads, transcript_data).

**Pseudocode:**

```python
function Round2(i, all_msg1s, internal_state, d_i, P_i, AllPublicKeys, cs, context):
    received_shares = new List<Scalar>()
    received_payloads = new Map<int, bytes>()

    for j from 1 to n:
        msg1_j = all_msg1s[j]
        C_j, PoP_j, E_j = msg1_j.C, msg1_j.PoP, msg1_j.E
        P_j = AllPublicKeys[j]

        if len(C_j) != t:
            abort("Invalid commitment length", j)
        if not Verify(public_key=C_j[0], signature=PoP_j, message=context || C_j || E_j):
            abort("Invalid PoP", j)

        # encrypted_shares[i] is the framed bytes uint64_be(len(c_ji)) || c_ji; unwrap with full bounds checks
        # before any slicing.
        framed_c_ji = msg1_j.encrypted_shares[i]
        if len(framed_c_ji) < 8:
            abort("Framed ciphertext shorter than 8-byte length prefix", j)
        L_ji = uint64_be_decode(framed_c_ji[0:8])
        if L_ji > MAX_CIPHERTEXT_SIZE:
            abort("Framed ciphertext length exceeds policy maximum", j)
        if len(framed_c_ji) != 8 + L_ji:
            abort("Framed ciphertext length mismatch (trailing bytes or short read)", j)
        c_ji = framed_c_ji[8:8 + L_ji]
        if len(c_ji) < scalar_size + AEAD_TAG_SIZE:
            abort("Ciphertext below minimum size", j)
        ecdh_secret = ecdh_encode(cs, d_i * E_j) || ecdh_encode(cs, d_i * P_j)
        (key, nonce) = DeriveKeyAndNonce(cs, ecdh_secret, E_j, P_j, P_i, context)
        plaintext = Decrypt(key, nonce, ciphertext=c_ji)
        if plaintext is null:
            abort("Decryption failed for participant j's ciphertext", j)

        if len(plaintext) < scalar_size:
            abort("Plaintext shorter than scalar size", j)
        s_ji = decode_scalar(plaintext[0:scalar_size])
        if s_ji is null:
            abort("Invalid scalar encoding", j)
        received_payloads[j] = plaintext[scalar_size:]

        if not VerifyShare(s_ji, i, C_j, cs.Group.G, t):
            abort("Invalid share", j)
        received_shares.append(s_ji)

    x_i = sum(received_shares)
    Y = sum(all_msg1s[j].C[0] for j in 1..n)
    Y_i = IdentityPoint()
    for k from 0 to t-1:
        C_agg_k = sum(all_msg1s[j].C[k] for j in 1..n)
        Y_i = Y_i + (power(i, k) * C_agg_k)

    if (x_i * cs.Group.G) != Y_i:
        abort("Final check failed")

    transcript_data = new TranscriptData(cs.id, all_msg1s, context, AllPublicKeys)
    return (x_i, Y, Y_i, received_payloads, transcript_data)
```

### Algorithm 6: COCKTAIL-DKG Round 3 (Participant `i`)

**Input:**

- `i`: The index of the current participant.
- `d_i`: The static private key of participant `i`.
- `P_j`: The static public key of each participant `j` from 1 to `n` (the ordered list `AllPublicKeys` used below
  includes `P_i` at index `i`; the signature-verification loop iterates over all `j` from 1 to `n` including
  `j = i`, verifying every CertEq signature on the shared transcript $T$).
- `transcript_data`: The public data from Round 2.
  The transcript includes:
  - len(ciphersuite_id) as uint64_le, ciphersuite_id bytes (UTF-8)
  - len(context) as uint64_le, context bytes
  - n as uint32_le, t as uint32_le
  - All static public keys P_j
  - All VSS commitments C_j
  - All PoP signatures PoP_j
  - All ephemeral public keys E_j
- `extension`: (Optional) Application-specific extension bytes (defaults to empty).

**Output:**

- `success`: A boolean indicating the protocol completed successfully.

**Steps:**

1. Construct Transcript:
    1. T = CanonicalEncode(transcript_data, extension)
2. Sign Transcript:
    1. sig_i = Sign(private_key=d_i, message=T)
3. Broadcast and Receive Signatures:
    1. Send sig_i to the coordinator.
    2. Receive all_signatures from the coordinator.
4. Verify All Signatures:
    1. For j from 1 to n:
        1. Let sig_j be the signature from participant j.
        2. valid_sig = Verify(public_key=P_j, signature=sig_j, message=T)
        3. If valid_sig is false, abort and blame participant j.
5. Success:
    1. success = true
6. Return success.

**Pseudocode:**

```python
function Round3(i, d_i, AllPublicKeys, transcript_data, extension=empty_bytes):
    T = CanonicalEncode(transcript_data, extension)
    sig_i = Sign(private_key=d_i, message=T)
    all_signatures = broadcast_and_receive(sig_i)

    for j from 1 to n:
        if not Verify(public_key=AllPublicKeys[j], signature=all_signatures[j], message=T):
            abort("Invalid transcript signature", j)

    return true


function CanonicalEncode(transcript_data, extension):
    T = empty_bytes
    T = T || uint64_le(len(transcript_data.ciphersuite_id))
    T = T || transcript_data.ciphersuite_id
    T = T || uint64_le(len(transcript_data.context))
    T = T || transcript_data.context
    T = T || uint32_le(transcript_data.n)
    T = T || uint32_le(transcript_data.t)
    for j from 1 to n:
        T = T || transcript_data.static_public_keys[j]
    for j from 1 to n:
        T = T || transcript_data.vss_commitments[j]
    for j from 1 to n:
        T = T || transcript_data.pop_signatures[j]
    for j from 1 to n:
        T = T || transcript_data.ephemeral_public_keys[j]
    T = T || uint64_le(len(extension))
    T = T || extension
    return T
```

## Appendix B: Test Vectors

This section provides test vectors for various threshold configurations (2-of-3, 3-of-5, and 7-of-14) across all
supported ciphersuites. The vectors were generated deterministically using a seed derived from the authors' names:

```
seed = SHA256("Daniel Bourdrez,Soatok Dreamseeker,Tjaden Hess")
     = b171b6992cc6db1f40b18dd8b1361d642f013e4b1208a735259a516af60dcb68
```

### Transparent Derivation Scheme

All secret values are derived using a labeled hash with ciphersuite and threshold domain separation:

```python
derived_bytes = H(seed || ciphersuite_id || uint32_le(t) || uint32_le(n) || label)
```

> **Note:** This labeled-hash construction is a deterministic test-vector seed expansion only. It is distinct from
> the protocol's $HashToScalar$ (used in the Schnorr scheme), which performs a near-uniform reduction with bias
> bounded by $\approx 2^{-128}$ (see [Schnorr Hash-to-Scalar Reduction](#schnorr-hash-to-scalar-reduction)). The test
> vectors use direct mod-$q$ reduction here purely for reproducibility; production deployments **MUST NOT** reuse
> this routine for protocol-level scalar derivation.

Where:

- `H` is the ciphersuite's hash function (e.g., SHA-512 for Ristretto255, SHA-256 for P-256)
- `ciphersuite_id` is the ciphersuite identifier string (e.g., "COCKTAIL(Ristretto255, SHA-512)")
- `t` is the threshold, encoded as a little-endian 32-bit unsigned integer
- `n` is the number of participants, encoded as a little-endian 32-bit unsigned integer
- `label` is a human-readable ASCII string identifying the value being derived

#### Labels

| Value                                | Label Format             | Example                |
|--------------------------------------|--------------------------|------------------------|
| Static secret key for participant i  | `static_secret_key_{i}`  | `static_secret_key_1`  |
| Round 1 RNG stream for participant i | `round1_participant_{i}` | `round1_participant_1` |
| Payload for participant i            | `payload_{i}`            | `payload_1`            |

#### Scalar Reduction

This is the seed-expansion-only reduction used to derive test-vector secret scalars from the labeled-hash
output above; it is **distinct** from the protocol's `HashToScalar` (see
[Schnorr Hash-to-Scalar Reduction](#schnorr-hash-to-scalar-reduction)) and exists only to make the test
vectors reproducible:

- For ciphersuites with 32-byte scalars and SHA-256 hash (P-256, secp256k1): the 32-byte hash output is
  reduced modulo the group order.
- For ciphersuites with SHA-512 or BLAKE2b-512 (Ed25519/Ristretto255, JubJub, Pallas): the 64-byte hash output
  is wide-reduced modulo the group order.
- For COCKTAIL(Ed448, SHAKE256) test-vector seed expansion: SHAKE256 is invoked with a **64-byte output** for
  this reduction (a single fixed length, distinct from the 56-byte $H6$ invocation and the 114-byte
  $HashToScalar$ invocation used elsewhere in the protocol); that 64-byte output is wide-reduced modulo the
  group order. The seed-expansion bias from a 64-byte input to a $\sim 446$-bit Ed448 scalar order is at
  most $2^{-128}$, which is sufficient for test-vector determinism.

This allows any developer to independently reproduce the test vectors by:

1. Computing `H(seed || ciphersuite_id || uint32_le(t) || uint32_le(n) || label)` for each value
2. Reducing the hash output to a scalar using the appropriate method

#### Context String Format

To satisfy all three Setup `context` MUSTs (session uniqueness, ordered participant binding, and verbatim
`ciphersuite_id` binding; see [Setup](#setup)), the test vectors use a context construction that includes
the test-vector tag, the canonical `ciphersuite_id` byte string, and the seed-derived participant public
keys:

```text
session_tag      = "COCKTAIL-DKG-TEST-VECTOR-{t}-OF-{n}"
context          = H( "COCKTAIL-DKG-CONTEXT"
                   || uint64_be(len(session_tag))   || session_tag
                   || uint64_be(len(ciphersuite_id)) || ciphersuite_id
                   || uint32_le(n)
                   || P_1 || P_2 || ... || P_n )
```

where $H$ is the ciphersuite's hash function and `ciphersuite_id` matches the test-vector header (e.g.,
`"COCKTAIL(Ristretto255, SHA-512)"`). When the test vectors are regenerated, each entry **MUST** record the
bare `session_tag` (as a `session_tag` field) alongside the derived `context` byte string (as a `context`
field or equivalent), so that implementations can independently reconstruct the `context` from $H$,
`session_tag`, `ciphersuite_id`, $n$, and the $P_j$ list, and verify byte-for-byte that their result matches
the published `context`. This is the same recommended construction described under [Setup](#setup); test
vectors do **not** use a separate context format from production deployments.

### Test Vector Types

Each ciphersuite includes the following test vector types:

1. **Basic vectors** (2-of-3, 3-of-5, 7-of-14): Standard DKG execution with empty extension.
2. **Payload extension vector** (2-of-3): Each participant includes a seed-derived payload with their encrypted shares.
   The extension is computed as a hash of the participant-ordered payloads:

   ```text
   ext = H(uint64_le(n) || uint64_le(len(payload_1)) || payload_1 || ... || uint64_le(len(payload_n)) || payload_n)
   ```

3. **Recovery vectors**: The 2-of-3 configuration of each ciphersuite includes recovery test data for participant 1
   (the 3-of-5 and 7-of-14 configurations omit recovery data).
   The participant-specific encrypted share bundle contains:
   - For each participant $j$ from 1 to $n$, the raw AEAD ciphertext $c_{j,1}$ from participant $j$ to
     participant 1, **listed in the table rows below as `Ciphertext from P{j}` and shown in bare (unframed)
     hex form**. To assemble the on-wire bundle $C^{rec}_1$ from these table rows, implementations
     concatenate the framed forms $\widetilde{c_{j,1}} = \mathrm{uint64\_be}(\mathit{len}(c_{j,1})) \parallel c_{j,1}$
     in participant order, as defined in [Protocol Messages](#protocol-messages) under $msg_{1|i}$. The table
     omits the length prefixes because (a) every ciphertext in these basic test vectors is the same fixed
     length (scalar encoding size plus AEAD authentication tag size, e.g. 48 bytes), so the prefixes carry no
     test-discriminating information, and (b) listing bare ciphertexts keeps the vectors aligned with the
     analogous JSON files in [CCTV](https://github.com/C2SP/CCTV/tree/main/cocktail-dkg).
   - The expected recovered secret share $x_1$.
   - The expected recovered verification share $Y_1$.

   These values enable implementers to verify their recovery implementation produces correct outputs when
   decrypting the framed bundle assembled from the listed ciphertexts using participant 1's static secret key
   and the transcript from the DKG session.

### Vector Data

The full, byte-for-byte authoritative test vector data is published as JSON files in
[CCTV](https://github.com/C2SP/CCTV/tree/main/cocktail-dkg), with one file per ciphersuite:

| Ciphersuite                     | CCTV file                               |
|---------------------------------|-----------------------------------------|
| COCKTAIL(Ed25519, SHA-512)      | `cocktail-dkg-ed25519-sha512.json`      |
| COCKTAIL(Ristretto255, SHA-512) | `cocktail-dkg-ristretto255-sha512.json` |
| COCKTAIL(Ed448, SHAKE256)       | `cocktail-dkg-ed448-shake256.json`      |
| COCKTAIL(P-256, SHA-256)        | `cocktail-dkg-p256-sha256.json`         |
| COCKTAIL(secp256k1, SHA-256)    | `cocktail-dkg-secp256k1-sha256.json`    |
| COCKTAIL(JubJub, BLAKE2b-512)   | `cocktail-dkg-jubjub-blake2b512.json`   |
| COCKTAIL(Pallas, BLAKE2b-512)   | `cocktail-dkg-pallas-blake2b512.json`   |

Each file contains the 2-of-3, 3-of-5, and 7-of-14 threshold configurations plus the 2-of-3 payload-extension variant;
each entry records `session_tag`, derived `context`, static keys, Round 1 outputs (ephemeral public keys, VSS 
commitments, PoPs, encrypted shares), Round 2 outputs (secret share, verification share), Round 3 transcript hash, the
final group public key, and (for the 2-of-3 configuration) recovery vectors with the ordered AEAD ciphertexts addressed
to participant 1. Implementations **MUST** reproduce these JSON files byte-for-byte from the deterministic derivation
procedure defined above.

The inline byte tables that previously appeared in this section are intentionally elided in favor of CCTV as
the single source of truth; the JSON format is mechanically parseable, less prone to copy-paste drift, and
versioned alongside other C2SP test vectors.
