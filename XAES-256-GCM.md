# The XAES-256-GCM extended-nonce AEAD

https://c2sp.org/XAES-256-GCM

This document specifies the XAES-256-GCM authenticated encryption with
additional data algorithm, based on the composition of a standard [NIST SP
800-108r1] KDF and the standard NIST AES-256-GCM AEAD ([NIST SP 800-38D], [FIPS
197]).

The XAES-256-GCM inputs are a 256-bit key, a 192-bit nonce, a plaintext of up to
approximately 64GiB, and additional data of up to 2 EiB.

Unlike AES-256-GCM, the XAES-256-GCM nonce can be randomly generated for a
virtually unlimited number of messages (2⁸⁰ messages with collision risk 2⁻³²).
Only a 256-bit key version is specified, which provides a comfortable multi-user
security margin. Like AES-256-GCM, XAES-256-GCM is not nonce misuse-resistant,
nor is it key-committing.

Compared to AES-256-GCM, XAES-256-GCM requires only three extra invocations of
the AES-256 encryption function for each message encryption and decryption (one
of which can be amortized across all uses of the same input key), and has
otherwise the same performance profile. The subkey derivation operation can be
described easily without reference to [NIST SP 800-108r1].

XAES-256-GCM can be easily implemented on top of any cryptography library that
exposes AES-256-GCM and one of [NIST SP 800-108r1] counter-based KDF, AES-256-CMAC,
AES-256-CBC, or the AES-256 block cipher, with no library modifications.

## Overview

XAES-256-GCM derives a subkey for use with AES-256-GCM ([NIST SP 800-38D], [FIPS
197]) from the input key and half the input nonce using a [NIST SP 800-108r1]
KDF, as described below. The derived key and the second half (last 96 bits) of
the input nonce are used to encrypt the message with AES-256-GCM.

The counter-based KDF ([NIST SP 800-108r1, Section 4.1]) is instantiated with
CMAC-AES256 ([NIST SP 800-38B]) and the input key as *Kin*, the ASCII letter `X`
(0x58) as *Label*, the first 96 bits of the input nonce as *Context* (as
recommended by [NIST SP 800-108r1, Section 4], point 4), a counter (*i*) size of
16 bits, and omitting the optional *L* field, to produce a 256-bit derived key.

Note that in this configuration the AES-CMAC input totals 128 bits, which fits
into a single block, mitigating the key control security issue described in
[NIST SP 800-108r1, Section 6.7] and allowing the PRF to be computed with a
single AES-256 encryption invocation.

It would in theory be possible to shrink *i* to 8 bits to fit a 8 bits *L*, but
some implementations unfortunately fix the *L* size to 32 bits. For
XAES-256-GCM, the length of the KDF output is fixed, so *L* can be safely
omitted.

Thanks to the choice of parameters, the overhead of implementing a [NIST SP
800-108r1] KDF compared to simply deriving the subkey by encrypting the nonce
half and a counter is minimal in terms of both complexity and performance: just
a single AES-256 invocation and some trivial bitwise operations. In return,
XAES-256-GCM can benefit from the analysis and compliance advantages of [NIST SP
800-108r1].

## Detailed key derivation algorithm

This section presents the full end-to-end algorithm with no references to [NIST
SP 800-38B] and [NIST SP 800-108r1] for implementation and analysis ease.

Inputs:

* 256-bit key *K*
* 192-bit nonce *N*

Outputs:

* 256-bit key *Kₓ*
* 96-bit nonce *Nₓ*

Algorithm:

1. *L* = AES-256ₖ(0x00, ..., 0x00)
2. If MSB₁(*L*) = 0, then *K1* = *L* << 1;  
   Else *K1* = (*L* << 1) ⊕ (0x00, ..., 0x00, 0b10000111)
3. *M1* = 0x00 || 0x01 || 0x58 || 0x00 || *N*[:12]
4. *M2* = 0x00 || 0x02 || 0x58 || 0x00 || *N*[:12]
5. *Kₓ* = AES-256ₖ(*M1* ⊕ *K1*) || AES-256ₖ(*M2* ⊕ *K1*)
6. *Nₓ* = *N*[12:]

*Kₓ* and *Nₓ* are then used as the AES-256-GCM key and nonce, respectively.

Note that Steps 1 and 2 can be precomputed and reused across every operation
that uses the same input key *K*.

The algorithm maps to [NIST SP 800-38B] and [NIST SP 800-108r1] as follows:

* Steps 1 and 2 reproduce the CMAC subkey generation specified in [NIST SP
  800-38B, Section 6.1]. Note that only *K1* is needed as the CMAC input is
  always a complete block.

* Steps 3 and 4 compose the PRF input messages for counter values *i* = { 1, 2 }
  according to [NIST SP 800-108r1, Section 4.1].

* Step 5 applies the CMAC PRF twice to the two single-block messages to derive
  the KDF output according to [NIST SP 800-38B, Section 6.2].

## Test vectors

In the following vectors, unquoted values are hex-encoded, and quoted values are
ASCII strings.

    K: 0101010101010101010101010101010101010101010101010101010101010101
    N: "ABCDEFGHIJKLMNOPQRSTUVWX"

    L: 7298caa565031eadc6ce23d23ea66378
    K1: e531954aca063d5b8d9c47a47d4cc6f0
    M1: 000158004142434445464748494a4b4c
    M2: 000258004142434445464748494a4b4c
    Kₓ: c8612c9ed53fe43e8e005b828a1631a0bbcb6ab2f46514ec4f439fcfd0fa969b
    Nₓ: 4d4e4f505152535455565758

    Plaintext: "XAES-256-GCM"
    AAD: ""
    Ciphertext: ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271

In the previous vector MSB₁(*L*) = 0, while in the following vector MSB₁ = 1.

    K: 0303030303030303030303030303030303030303030303030303030303030303
    N: "ABCDEFGHIJKLMNOPQRSTUVWX"

    L: 91c08762876dccf9ba204a33768fa5fe
    K1: 23810ec50edb99f374409466ed1f4b7b
    M1: 000158004142434445464748494a4b4c
    M2: 000258004142434445464748494a4b4c
    Kₓ: e9c621d4cdd9b11b00a6427ad7e559aeedd66b3857646677748f8ca796cb3fd8
    Nₓ: 4d4e4f505152535455565758

    Plaintext: "XAES-256-GCM"
    AAD: "c2sp.org/XAES-256-GCM"
    Ciphertext: 986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d

### Accumulated randomized tests

For each test, the following structure (presented according to [RFC 8446,
Section 3]) is read from a deterministic RNG, and the ciphertext is hashed.

The deterministic RNG is a single SHAKE-128 instance with an empty input. (The
RNG stream starts with `7f9c2ba4e88f827d616045507605853e`.) The hash is a
separate SHAKE-128 instance.

    opaque key[32];
    opaque nonce[24];
    opaque plaintext<0..255>;
    opaque aad<0..255>;

The resulting hash for 10 000 iterations is

    e6b9edf2df6cec60c8cbd864e2211b597fb69a529160cd040d56c0c210081939

The resulting hash for 1 000 000 iterations is

    2163ae1445985a30b60585ee67daa55674df06901b890593e824b8a7c885ab15

## Alternatives

The goal of this design is to provide an AES-based AEAD with safely randomizable
nonces and solid multi-user security margins, as a robust abstraction that
doesn't require users to reason about nonce or key sizes. There are many ways to
achieve that goal. This document chooses a composition of standard building
blocks, with an eye to FIPS 140 compliance.

We could use HMAC or KMAC instead of CMAC, or HKDF instead of a [NIST SP
800-108r1] KDF, but that would introduce a dependency on a hash function, which
we avoid with the current design. [NIST SP 800-108r1] recommends against CMAC
"unless, for example, AES is the only primitive implemented in the platform or
using CMAC has a resource benefit", which applies to us. It goes on to explain
that the issue with CMAC is one of [key control security](https://scottarc.blog/2024/06/04/attacking-nist-sp-800-108/),
which we mitigate by limiting the CMAC input to a single block.

We could simply apply the AES-256 encryption function to a concatenation of a
counter and half the nonce, without the extra scaffolding necessary to call it
"CMAC". That would save little complexity and resources, while missing out on
the compliance advantages of complying with [NIST SP 800-108r1].

Using AES-GCM with 128-bit nonces is possible, but does not do what users might
expect: when the nonce is not 96 bits, instead of concatenating the nonce with a
32-bit counter, the nonce is hashed and used as the starting counter. This means
that the AES-CTR collision probability becomes a function not only of the number
of messages but also of their length. Mid-message AES-CTR collisions are harder
to detect than nonce collisions, and they compromise the confidentiality only of
colliding messages, instead of the authentication of all messages under the same
key, but are still undesirable. Since the goal is providing a clean abstraction,
we wish to avoid having to make users think about maximum message sizes while
evaluating bounds. Read more at [Galois/Counter Mode and random nonces](https://neilmadden.blog/2024/05/23/galois-counter-mode-and-random-nonces/).

Users could use AES-GCM-SIV (specifically, AEAD_AES_256_GCM_SIV) from [RFC
8452]. AES-GCM-SIV is more complex, less widely available, slightly less
performant, and not FIPS 140 compliant, but has the advantage of being
nonce-misuse resistant. Libraries that abstract away nonce generation by reading
bytes from the OS CSPRNG can minimize the risk of nonce reuse with XAES-256-GCM
on any properly functioning modern system.

Note that AES-GCM-SIV still has 96-bit nonces, so no more than 2³² messages can
be encrypted unless nonce reuse is tolerable. AES-GCM-SIV is resistant to nonce
reuse in the sense that it only allows an attacker to detect identical messages
if nonces are reused. If that is acceptable, the analysis for how many messages
can be safely encrypted with random nonces [is complicated][RFC 8452, Section 9]
and was amended multiple times. The specification provides bounds for
*ciphertext indistinguishability* which is a somewhat overly strict goal for an
AES-CTR-based scheme, as the distinguishing "attack" is just noticing that
blocks don't repeat even after they would be expected to in a random stream,
because AES is a PRP. NIST itself doesn't care about that for AES-GCM and
provides bounds that exceed the single-key AES indistinguishability bounds. The
result is a table that has to take into account the maximum message size, and
that has worse bounds than AES-GCM for messages longer than 8GiB. Again, that's
probably an artifact of the ciphertext indistinguishability goal, but it adds
complexity and confusion for the adopter. (All this is what AES-GCM-SIV refers
to when claiming better-than-birthday bounds. In that sense, XAES-256-GCM also
achieves better-than-birthday bounds.)

[Double-Nonce-Derive-Key-GCM] (DNDK-GCM) by Shay Gueron is a very similar scheme
that also derives an AES-256-GCM key from a 256-bit key and a 192-bit nonce,
with nearly identical goals. (It has optional support for key commitment, which
XAES-256-GCM does not.) Its key derivation function costs six AES invocations
(as opposed to three in XAES-256-GCM) but doesn't use the underlying AES-256-GCM
nonce. Its authors claim FIPS 140 compliance due to the use of AES-256-GCM, but
the KDF does not appear to comply with any NIST standard. It is reportedly used
in production at Meta.

Soatok proposed in 2022 [AES-XGCM], a very similar scheme to XAES-256-GCM that
also uses CMAC to derive an AES-GCM key from a 192-bit nonce. The use of CMAC in
XAES-256-GCM is slightly more efficient, and compliant with NIST SP 800-108r1.

[AES-GEM] is a nonce-extended mode presented at the NIST workshop on the
requirements for an accordion mode cipher. It also uses CMAC for subkey
derivation, but not according to NIST SP 800-108r1, and it doesn't claim current
FIPS 140 compliance. It also reallocates part of the AES-GCM nonce to counter
space, encrypts the GHASH output to improve the security of tag truncation, and
offers optional key commitment. These tweaks are incompatible with FIPS 140
compliance at this time.

There are novel AEAD designs that reuse AES internals for performance and have
our desired properties, such as [AEGIS] or the [OCH / GCH / CIV AEAD family].
Again, they are not standard compliant and not as widely available.

AES-256-GCM is desirable for its longer key, but is also unfortunately defined
to run more rounds than AES-128-GCM, affecting performance. It would be nice to
define a [reduced-round variant], but it would break standard compliance.

AES-256-GCM counter-intuitively has less security margin than AES-128-GCM given
the same number of rounds because of AES's poor key schedule. Since we are
deriving keys, we could decide to rip out the AES key schedule and just derive
round subkeys, resolving the issue and improving the cipher. That would
obviously be non-standard, and would require us to use a hash-based key
derivation.

[NIST SP 800-38D]: https://csrc.nist.gov/pubs/sp/800/38/d/final
[FIPS 197]: https://csrc.nist.gov/pubs/fips/197/final
[NIST SP 800-38B]: https://csrc.nist.gov/publications/detail/sp/800-38b/final
[NIST SP 800-38B, Section 6.1]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38B.pdf#%5B%7B%22num%22%3A30%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C70%2C637%2C0%5D
[NIST SP 800-38B, Section 6.2]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38B.pdf#%5B%7B%22num%22%3A30%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C70%2C248%2C0%5D
[NIST SP 800-108r1]: https://csrc.nist.gov/publications/detail/sp/800-108/rev-1/final
[NIST SP 800-108r1, Section 4]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf#%5B%7B%22num%22%3A71%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C70%2C720%2C0%5D
[NIST SP 800-108r1, Section 4.1]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf#%5B%7B%22num%22%3A79%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C70%2C300%2C0%5D
[NIST SP 800-108r1, Section 6.7]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf#%5B%7B%22num%22%3A163%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C70%2C645%2C0%5D
[RFC 8452]: https://www.rfc-editor.org/info/rfc8452
[reduced-round variant]: https://words.filippo.io/dispatches/xaes-256-gcm-11/
[AEGIS]: https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/
[RFC 8452, Section 9]: https://www.rfc-editor.org/rfc/rfc8452.html#section-9
[RFC 8446, Section 3]: https://www.rfc-editor.org/rfc/rfc8446.html#section-3
[Double-Nonce-Derive-Key-GCM]: https://iacr.org/submit/files/slides/2024/rwc/rwc2024/105/slides.pdf
[AES-XGCM]: https://soatok.blog/2022/12/21/extending-the-aes-gcm-nonce-without-nightmare-fuel/
[OCH / GCH / CIV AEAD family]: https://www.youtube.com/watch?v=7GBzKytVjH4
[AES-GEM]: 
