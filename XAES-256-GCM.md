This document specifies the XAES-256-GCM authenticated encryption with
additional data algorithm, based on the composition of a standard [NIST SP
800-108r1] KDF and the standard NIST AES-256-GCM AEAD.

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

## Overview

XAES-256-GCM derives a subkey for use with AES-256-GCM from the input key and
half the input nonce using a [NIST SP 800-108r1] KDF, as described below. The
derived key and the second half (last 96 bits) of the input nonce are used to
encrypt the message with AES-256-GCM.

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

1. *L* = AES-256ₖ(0¹²⁸)
2. If MSB₁(*L*) = 0, then *K1* = *L* << 1;
   Else *K1* = (*L* << 1) ⊕ 0¹²⁰10000111
3. *M1* = 0x00 || 0x01 || `X` || 0x00 || *N*[:12]
4. *M2* = 0x00 || 0x02 || `X` || 0x00 || *N*[:12]
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

[NIST SP 800-38B]: https://csrc.nist.gov/publications/detail/sp/800-38b/final
[NIST SP 800-38B, Section 6.1]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38B.pdf#%5B%7B%22num%22%3A30%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C70%2C637%2C0%5D
[NIST SP 800-38B, Section 6.2]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38B.pdf#%5B%7B%22num%22%3A30%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C70%2C248%2C0%5D
[NIST SP 800-108r1]: https://csrc.nist.gov/publications/detail/sp/800-108/rev-1/final
[NIST SP 800-108r1, Section 4]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf#%5B%7B%22num%22%3A71%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C70%2C720%2C0%5D
[NIST SP 800-108r1, Section 4.1]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf#%5B%7B%22num%22%3A79%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C70%2C300%2C0%5D
[NIST SP 800-108r1, Section 6.7]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-108r1.pdf#%5B%7B%22num%22%3A163%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C70%2C645%2C0%5D
