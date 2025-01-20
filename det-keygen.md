# Deterministic Key Generation

[c2sp.org/det-keygen](https://c2sp.org/det-keygen)

## Introduction

Modern algorithms like ML-KEM and Ed25519 provide a well-specified process to
generate a key from a fixed-length sequence of random bytes, commonly referred
to as a seed. That process is deterministic, meaning that the same seed will
always produce the same key.

This is sometimes useful when deriving keys from a fixed secret, but most
importantly it allows generating known-answer test vectors for key generation
algorithms, even when they're ordinarily only applied to the output of a CSPRNG.
These vectors can be carefully selected to explore rare edge cases, and can be
shared across implementations.

Older algorithms, like RSA and ECDSA, lack such a seed-based key generation
process. Instead, they rely on an abstract random bit generator to produce a
variable number of bit (not byte) strings.

This document bridges the gap by describing a seed-based deterministic key
generation process for ECDSA. The process is compliant with the algorithms
described in [FIPS 186-5], reuses where possible functions that libraries are
likely to have already implemented, and is simplified by targeting only
production parameters.

## ECDSA

At a high level, this ECDSA key generation process involves instantiating
HMAC_DRBG with SHA-256, the seed, and a per-curve personalization string;
converting a bit string from the DRBG into a scalar with bits2int; and retrying
(up to once, and only for P-256) if it overflows the order of the curve.

Below, HMAC(K, M) denotes the 32-byte HMAC of message M with key K computed with
hash function SHA-256.

**Input**:

1. *seed* — A byte string. The seed MUST be at least 128 bits (16 bytes) long,
   and SHOULD include at least 192 bits of entropy to provide a security margin
   against multi-target attacks.

2. *n*, *G* — The order and generator of the target curve. The target curve MUST
   be one of NIST P-224, P-256, P-384, or P-521, defined in [SP 800-186].

   Targeting specific curves lets us quantify the concrete probabilities of
   various edge cases.

**Output**:

1. *d*, *Q* — The generated private and public key. *d* is an integer in the
   range [1, *n*–1], and *Q* is a point on the target curve.

**Process**:

1. Set *personalization_string* to

   1. `det ECDSA key gen P-224` if the target curve is P-224;

   2. `det ECDSA key gen P-256` if the target curve is P-256;
   
   3. `det ECDSA key gen P-384` if the target curve is P-384;
   
   4. `det ECDSA key gen P-521` if the target curve is P-521.

2. *K* = 0x00 0x00 ... 0x00, where *K* is 256 bits long.

3. *V* = 0x01 0x01 ... 0x01, where *V* is 256 bits long.

4. *K* = HMAC(*K*, *V* || 0x00 || *seed* || *personalization_string*)

5. *V* = HMAC(*K*, *V*)

6. *K* = HMAC(*K*, *V* || 0x01 || *seed* || *personalization_string*)

7. *V* = HMAC(*K*, *V*)

8. *temp* = ""

9. While len(*temp*) < len(*n*):

   1. *V* = HMAC(*K*, *V*)

   2. *temp* = *temp* || *V*

   This loop runs once for P-224 and P-256, twice for P-384,
   and three times for P-521.

10. *d* = bits2int(*temp*)

    bits2int is defined in [RFC 6979, Section 2.3.2].
    It interprets the leftmost len(*n*) bits as a big-endian integer.

    For P-224, *temp* is truncated at 28 bytes.
    For P-256, *temp* is used as-is.
    For P-384, *temp* is truncated at 48 bytes.
    For P-521, where len(*n*) is not a multiple of 8, *temp* is truncated at 66
    bytes, and then right-shifted by 7 bits.[^bits2int]

11. If the target curve is P-256[^retry] and *d* ≥ *n*:

    1. *K* = HMAC(*K*, *V* || 0x00)

    2. *V* = HMAC(*K*, *V*)

    3. Repeat steps 8–10.

    This occurrence SHOULD be specifically tested, and can be reached with a
    *seed* value of `b432f9be30890480298218510559aed7` (in hex).

12. If *d* = 0 or *d* ≥ *n*, return a fatal error.

    This occurrence has cryptographically negligible chance, and if encountered
    it suggests implementation error or hardware failure.

13. *Q* = [*d*]*G*

14. Return (*d*, *Q*)

[^bits2int]: It would be simpler and less error-prone to mask the leftmost bits of *temp* in
    step 10, instead of performing a right shift for P-521. However, bits2int is
    already used as part of signature generation for encoding the hash, and for
    deterministic nonce generation. Using it here makes it easier to reuse existing
    and tested code.

    In particular, note how the process is analogous to the deterministic nonce
    generation of [RFC 6979], and to the hedged nonce generation of
    [draft-irtf-cfrg-det-sigs-with-noise-04], which generate (*k*, *R*) pairs
    analogous to (*d*, *Q*). The only differences are the HMAC_DRBG seed, nonce, and
    personalization string in steps 4 and 6, as well as the hash function. Nonce
    generation uses the hash function that generated the message digest, while key
    generation always uses SHA-256.

[^retry]: Since *d* is drawn from a DRBG as part of the algorithm, regardless of
    the quality of the seed, the probability of *d* ≥ *n* is:
    [< 2⁻¹¹²](https://www.wolframalpha.com/input?i=log2%281+-+26959946667150639794667015087019625940457807714424391721682722368061+%2F+2%5E224%29) for P-224;
    [< 2⁻³²](https://www.wolframalpha.com/input?i=log2%281+-+115792089210356248762697446949407573529996955224135760342422259061068512044369+%2F+2%5E256%29) for P-256;
    [< 2⁻¹⁹⁴](https://www.wolframalpha.com/input?i=log2%281+-+39402006196394479212279040100143613805079739270465446667946905279627659399113263569398956308152294913554433653942643+%2F+2%5E384%29) for P-384; and
    [< 2⁻²⁶²](https://www.wolframalpha.com/input?i=log2%281+-+6864797660130609714981900799081393217269435300143305409394463459185543183397655394245057746333217197532963996371363321113864768612440380340372808892707005449+%2F+2%5E521%29) for P-521.

    Of these, the P-256 case is the only one with non-negligible probability, and
    it's practically reachable in testing and in production.

### NIST FIPS 186-5 compliance

The algorithm is equivalent to following [FIPS 186-5, Appendix A.2.2], *ECDSA
Key Pair Generation by Rejection Sampling*, using HMAC_DRBG from [SP 800-90A Rev. 1].

If FIPS 186-5 and SP 800-90A Rev. 1 compliance is required, the seed MUST be
generated from a compliant DRBG, and MUST contain at least 168, 192, 288, and
384 bits of entropy for P-224, P-256, P-384, and P-521, respectively.
(That's 3/2 of the requested security strength, allowing omission of the DRBG
nonce per [SP 800-90A Rev. 1, Section 8.6.7] and [SP 800-57 Part 1 Rev. 5,
Section 5.6.1.1].)

SHA-256 is sufficient for the requested security strength of all three curves,
per [SP 800-90A Rev. 1, Section 10.1] and [SP 800-57 Part 1 Rev. 5, Section 5.6.1.2].

Steps 2–7 instantiate HMAC_DRBG per [SP 800-90A Rev. 1, Section 10.1.2.3].
Steps 8–9 (and 11.1–11.2) generate a bit string per [SP 800-90A Rev. 1, Section 10.1.2.5].
Steps 10 and 12 convert the bit string with a process equivalent to [FIPS 186-5,
Appendix A.4.2].
Steps 13–14 complete the [FIPS 186-5, Appendix A.2.2] process.

Despite being called a *Rejection Sampling* method, [FIPS 186-5, Appendix A.2.2]
returns ERROR when the first sample is out of range.
When the target curve is P-256, this can be encountered in practice at scale.[^retry]
Step 11 simulates returning an error and then rerunning the whole process,
generating a new bit string from the DRBG.

[FIPS 186-5, Appendix A.4.2], checks x ≤ N - 2 and then returns x + 1.
Checking 0 < x ≤ N - 1 is strictly equivalent but is easier to implement, as it
doesn't require an addition, and libraries might already have APIs to check if a
scalar is in range and if it's zero.
Equivalent processes are explicitly allowed by point 4 of [FIPS 186-5, Appendix A.2.2].

[FIPS 186-5]: https://doi.org/10.6028/NIST.FIPS.186-5
[FIPS 186-5, Appendix A.2.2]: https://doi.org/10.6028/NIST.FIPS.186-5#%5B%7B%22num%22%3A156%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C70%2C409%2C0%5D
[FIPS 186-5, Appendix A.4.2]: https://doi.org/10.6028/NIST.FIPS.186-5#%5B%7B%22num%22%3A172%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C70%2C319%2C0%5D
[SP 800-186]: https://doi.org/10.6028/NIST.SP.800-186
[SP 800-57 Part 1 Rev. 5, Section 5.6.1.1]: https://doi.org/10.6028/NIST.SP.800-57pt1r5#%5B%7B%22num%22%3A193%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C70%2C529%2C0%5D
[SP 800-57 Part 1 Rev. 5, Section 5.6.1.2]: https://doi.org/10.6028/NIST.SP.800-57pt1r5#%5B%7B%22num%22%3A199%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C70%2C326%2C0%5D
[SP 800-90A Rev. 1]: https://doi.org/10.6028/NIST.SP.800-90Ar1
[SP 800-90A Rev. 1, Section 10.1]: https://doi.org/10.6028/NIST.SP.800-90Ar1
[SP 800-90A Rev. 1, Section 10.1.2.3]: https://doi.org/10.6028/NIST.SP.800-90Ar1
[SP 800-90A Rev. 1, Section 10.1.2.5]: https://doi.org/10.6028/NIST.SP.800-90Ar1
[SP 800-90A Rev. 1, Section 8.6.7]: https://doi.org/10.6028/NIST.SP.800-90Ar1
[RFC 6979]: https://rfc-editor.org/rfc/rfc6979.html
[RFC 6979, Section 2.3.2]: https://rfc-editor.org/rfc/rfc6979.html#section-2.3.2
[draft-irtf-cfrg-det-sigs-with-noise-04]: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-det-sigs-with-noise-04
