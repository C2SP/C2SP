# ChaCha20-Poly1305-SIV
[https://c2sp.org/chacha20-poly1305-siv](https://c2sp.org/chacha20-poly1305-siv)

- **Version**: v0.0.1
- **Author**: Samuel Lucas

This document specifies the misuse-resistant, key-committing ChaCha20-Poly1305-SIV (CCP-SIV) authenticated encryption with associated data (AEAD) scheme. It is built from ChaCha20 and Poly1305 without modifying their designs, making it compatible with existing APIs from cryptographic libraries. Furthermore, the overhead is just two ChaCha20 blocks over ChaCha20-Poly1305 whilst supporting a larger nonce.

## Introduction
At the time of writing, [ChaCha20-Poly1305](https://datatracker.ietf.org/doc/html/rfc8439) is one of the [most popular](https://ianix.com/pub/chacha-deployment.html) AEAD schemes in practice. For example, it is supported in TLS, SSH, IPsec, WireGuard, and so on. However, it has four major limitations that affect its generic security, namely, it is not [misuse-resistant](https://eprint.iacr.org/2006/221), [committing](https://eprint.iacr.org/2022/268), [context unforgeability secure](https://eprint.iacr.org/2024/733), or [context discoverability secure](https://eprint.iacr.org/2023/526). The latter three stemming from the definition of a secure AEAD being flawed, failing to account for collision resistance, second-preimage resistance, and preimage resistance. This means:

1. Nonce reuse reveals the XOR of the plaintexts, affecting confidentiality, and recovery of the authentication key allows [forgery](https://eprint.iacr.org/2017/239), affecting integrity.
2. It is possible to create a ciphertext that successfully decrypts with multiple different parameters (e.g., different keys, nonces, or associated data), which can affect integrity and confidentiality depending on the [scenario](https://eprint.iacr.org/2023/526).
3. Given knowledge of the parameters used for encryption, it may be possible to find a different set of parameters such that decryption of a ciphertext succeeds, which is related to integrity but needs further investigation.
4. Given knowledge of certain parameters (e.g., the key and nonce but not the associated data), it is possible to compute a value for the remaining parameter(s) such that decryption of a ciphertext succeeds, which can impact integrity but has received little investigation [thus far](https://eprint.iacr.org/2024/928).

These issues have led to [real-world](https://eprint.iacr.org/2016/475) [attacks](https://www.usenix.org/conference/usenixsecurity22/presentation/albertini). It is undeniable that [systems go wrong](https://www.ndss-symposium.org/ndss2010/when-good-randomness-goes-bad-virtual-machine-reset-vulnerabilities-and-hedging-deployed/), [users make mistakes](https://www.daemonology.net/blog/2011-01-18-tarsnap-critical-security-bug.html), and people's understanding of security properties is [incomplete](https://eprint.iacr.org/2019/016). A *secure by default* approach minimises harm and takes some burden off the user, placing it in the hands of those with more experience. And ChaCha20-Poly1305 is an ideal candidate for this given that it already performs more than one pass over the message and requires a one-time message authentication code (MAC) key, which prevents static associated data pre-processing.

We therefore specify ChaCha20-Poly1305-SIV (CCP-SIV) to fill this gap, providing an alternative to [AES-GCM-SIV](https://datatracker.ietf.org/doc/html/rfc8452). It has the following advantages over similar schemes:

- Only two ChaCha20 blocks of overhead over ChaCha20-Poly1305 (aka one block of overhead over XChaCha20-Poly1305), one of which is unavoidable for SIV. The plaintext and associated data are not processed by a collision-resistant hash function or processed twice for the tag computation. Furthermore, the performance is roughly equivalent for encryption/decryption.
- A 128-bit nonce for more random nonces with virtually no performance penalty. Moreover, the number of nonce repetitions before security is lost [should](https://eprint.iacr.org/2025/222) exceed AES-GCM-SIV. Lastly, a dedicated parameter rightly encourages nonce usage for semantic security, avoids having to concatenate a nonce to any associated data, and provides security benefits like rekeying.
- Strong key-committing and context discoverability security. [Most schemes](https://eprint.iacr.org/2023/526) have no committing or context discoverability security, and even committing schemes, like [Ascon-AEAD128](https://csrc.nist.gov/pubs/sp/800/232/ipd), typically have [weak](https://eprint.iacr.org/2023/1525) (e.g., 64-bit) committing security.
- Only ChaCha20 and Poly1305 are used, which are both specified in an RFC. [HChaCha20](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha), a non-ChaCha20/Poly1305 primitive, and/or [S2V](https://datatracker.ietf.org/doc/html/rfc5297#section-2.4) are not required.
- Existing APIs can be used for implementation assuming access to the ChaCha20 counter, which is required to implement ChaCha20-Poly1305. This makes adoption easy.
- Existing and future security analyses of ChaCha20 and Poly1305 apply directly as no modifications are made to their designs.
- There are no variants, simplifying implementation, eliminating user confusion, and providing better multi-user/multi-key security due to the 256-bit key.

With that said, it has the following disadvantages:

- A 256-bit tag, meaning 128 bits of expansion over popular AEAD schemes. However, this provides strong key-committing security with optimal performance and is less than/equivalent to non-committing AEADs with [commitment transforms](https://eprint.iacr.org/2025/320) applied. Furthermore, some generic composition schemes and [newer](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aegis-aead) [AEADs](https://datatracker.ietf.org/doc/html/draft-nakano-rocca-s) use 256-bit tags.
- No context commitment, which would provide better generic security. However, this is not possible using just ChaCha20/Poly1305 with existing APIs. For example, it could be done by [carefully](https://tosc.iacr.org/index.php/ToSC/article/view/589) instantiating the keyed sponge construction with the ChaCha20 permutation (no feed-forward). Fortunately, it is [easy](https://eprint.iacr.org/2022/268) to make a key-committing scheme context committing, and protocols may not allow attacker control over the associated data.
- ChaCha20 is used for commitment instead of a collision-resistant hash function, which is not what ChaCha20 was designed for. However, the literature [supports](https://eprint.iacr.org/2025/222) this usage.
- Poly1305 provides a [much weaker security level](https://eprint.iacr.org/2023/085) than ChaCha20 and other hash functions. However, a newer hash function like [Poly1503 or Poly2663](https://eprint.iacr.org/2025/464) would take significant time to adopt/deploy whilst still suffering from a lack of collision resistance, essentially ignoring the committing security problem. A larger tag also introduces more overhead for masking the output.
- It is not possible to begin encrypting until the tag has been computed due to the misuse-resistance property. However, ChaCha20-Poly1305 already does separate passes for encryption and authentication, with these operations not being [interleaved](https://eprint.iacr.org/2015/102) for performance like in AES-GCM.

Further design rationale can be found towards the end of this document.

### Comparison to Other Designs
[AES-SIV](https://eprint.iacr.org/2006/221) originated in 2006 to address the key-wrap problem and became an [RFC](https://datatracker.ietf.org/doc/html/rfc5297) in 2008. It uses AES-CMAC with the novel S2V construction for authenticating a vector of strings (rather than concatenating them with length encoding to become a single string) and an AES-CTR variant for encryption. It takes a larger key that is split in half, uses the tag as the counter, clears certain bits in the counter for optimisation reasons, prepends the tag, and S2V enables inputs to be processed in parallel and cached whilst helping with efficiency in the case of CMAC. However, AES-SIV [lacks committing security](https://eprint.iacr.org/2023/526), is limited to 2<sup>48</sup> invocations with the same key, has multiple variants, has no nonce parameter despite use being recommended (and mandatory in the RFC), and S2V is more error prone to implement than concatenation or constructions [like NMAC](https://neilmadden.blog/2021/10/27/multiple-input-macs/).

[AES-GCM-SIV](https://eprint.iacr.org/2017/168) was published in 2017 to improve upon [GCM-SIV](https://eprint.iacr.org/2015/102) from 2015 and became an [RFC](https://datatracker.ietf.org/doc/html/rfc8452) in 2019. Compared to AES-GCM, it allows more plaintexts to be encrypted under the same key by deriving subkeys based on the nonce, enforces a 96-bit nonce and 128-bit tag, switches to little-endian encoding for performance, encrypts the authenticator output, and uses the tag (modified for domain separation) as the counter. However, it has slower encryption than decryption ([up to 50% slower encryption](https://eprint.iacr.org/2025/222) than AES-GCM), a [suboptimal](https://eprint.iacr.org/2018/136) truncation-based key derivation function (KDF) that introduces four or six additional AES calls, cannot precompute associated data, is meant to be used with random nonces, and still has quite stringent usage limits (e.g., 64 GiB of plaintext). Moreover, like AES-GCM, it [lacks committing security](https://www.usenix.org/conference/usenixsecurity21/presentation/len), works best with hardware support, has multiple variants, and cannot be implemented with existing APIs like ChaCha20-Poly1305 and co can.

[XChaCha20-HMAC-SHA256-SIV](https://datatracker.ietf.org/doc/html/draft-madden-generalised-siv) was first specified in 2018 but never moved beyond an Internet-Draft. It requires a non-ChaCha20/Poly1305 primitive, is less efficient (due to collision-resistant hashing and S2V typically being slower than concatenation), is more error prone to implement due to S2V (no existing APIs), takes a larger key that gets split in half, prepends the tag, and has no nonce parameter despite a minimum length of 1 byte and recommending that a nonce should be used for semantic security. Furthermore, the committing security has not been investigated to our knowledge. Finally, there is only one test vector when multiple are required, with the reference implementation not matching the specification. However, it also uses a 256-bit tag and does nonce extension for encryption.

[CCM-SIV](https://eprint.iacr.org/2019/892) appeared in 2019, targeting embedded devices by only requiring a single primitive (AES) for encryption and authentication. Despite the name, it is not an SIV variant of AES-CCM. Instead, it takes inspiration from work related to GCM-SIV and AES-GCM-SIV. It sports a 128-bit nonce and derives three static 128-bit subkeys (two for the MAC and one for encryption), allowing them to be cached for the same key. A custom CBC-based MAC is then used to derive a 128-bit tag that becomes the IV for CTR mode, with the least significant 32 bits as a counter. However, the key size is undefined, the KDF produces subkeys that are not truly random, the scheme is restricted to 2<sup>32</sup> blocks of plaintext, the MAC cannot be parallelised, the committing security has not been studied to our knowledge, and it cannot be implemented with existing APIs like ChaCha20-Poly1305 can.

[XChaCha20-SIV](https://github.com/jedisct1/libsodium-xchacha20-siv) was developed in 2020. It lacks a specification and test vectors, requires keyed BLAKE2b-512 and BLAKE2b-256, uses a custom variant of S2V plus S2V is regularly slower (serially and in parallel) than concatenation with length encoding, is more difficult to implement due to S2V (no existing APIs), derives static subkeys, has an optional nonce parameter, and its committing security has not been analysed. However, it also has a 256-bit tag and does nonce extension for encryption.

[ChaCha-Daence](https://eprint.iacr.org/2020/067) was published in 2020. Like our design, it can be easily implemented using existing APIs. However, it makes three HChaCha20 calls, has two Poly1305 instances to improve the security level, takes a larger key rather than performing subkey derivation, pads 128-bit keys for Poly1305, has no nonce parameter, and uses a 192-bit tag that gets prepended. The additional Poly1305 call significantly reduces performance for all message lengths when implemented serially. In parallel, the performance is even worse for small messages, reasonable for medium-length messages, and competitive for very large messages. However, this complicates implementation. Lastly, while no claim is made about key commitment, it can be argued to be key committing based on the literature.

[ChaCha20-Poly1305-PSIV](https://eprint.iacr.org/2025/222) was proposed in 2025. It only computes one additional ChaCha20 block over ChaCha20-Poly1305 whilst being misuse-resistant and key committing. The Poly1305 key can also be cached to make the number of ChaCha20 blocks equivalent and to allow static associated data pre-processing. Then the usage limits are more relaxed than AES-GCM-SIV. However, it requires modifying the ChaCha20 state, meaning existing APIs cannot be used. Furthermore, the constant in the state is reduced from 128 bits to 32 bits, meaning security analyses of ChaCha20 no longer directly apply. The tag size is also only 128 bits, offering 64-bit key-committing security, which is below the [minimum recommended amount](https://eprint.iacr.org/2022/1260) due to the potential of an [offline attack](https://eprint.iacr.org/2024/875). Whilst the tag size could be increased, this would decrease the nonce size, which is already smaller than ideal, when trying to use more of the tag for encryption. Then the Poly1305 key caching cannot be used with a one-shot API.

## Conventions and Definitions
The key words “**MUST**”, “**MUST NOT**”, “**REQUIRED**”, “**SHALL**”, “**SHALL NOT**”, “**SHOULD**”, “**SHOULD NOT**”, “**RECOMMENDED**”, “**NOT RECOMMENDED**”, “**MAY**”, and “**OPTIONAL**” in this document are to be interpreted as described in BCP 14 [[RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119)] [[RFC 8174](https://datatracker.ietf.org/doc/html/rfc8174)] when, and only when, they appear in all capitals, as shown here.

Throughout this document, “byte” refers to the same unit as “octet”, namely an 8-bit sequence.

Operations:
- `a || b`: the concatenation of byte arrays `a` and `b`.
- `a[i..j]`: the slice of byte array `a` from index `i` (inclusive) to index `j` (exclusive).
- `ByteArray(l)`: the creation of a new, all-zero byte array with length `l`.
- `ReadLE32(a)`: the little-endian conversion of byte array `a` into an unsigned 32-bit integer (uint32).
- `ConstantTimeEquals(a, b)`: the constant-time comparison of byte arrays `a` and `b`, which returns `true` if the two arrays are equal and `false` otherwise.
- `Wipe(a)`: the zeroing of byte array `a` in a way that cannot be optimised away by the compiler.
- `ChaCha20(key, counter, nonce, plaintext)`: the ChaCha20 encryption algorithm, as defined in [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439). Note that this is not the same as Bernstein's [original ChaCha20](https://cr.yp.to/chacha/chacha-20080128.pdf), which has a different counter/nonce size.
- `Poly1305(key, associatedData, plaintext)`: the Poly1305 algorithm with the message inputs ordered, padded, and length encoded following ChaCha20-Poly1305 (replacing the ciphertext with the plaintext), as defined in [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439).

Constants:
- `K_LEN`: the length of the encryption key, which is 32 bytes.
- `N_LEN`: the length of the nonce, which is 16 bytes.
- `A_MAX`: the maximum associated data length, which is 2<sup>38</sup> bytes (256 GiB).
- `P_MAX`: the maximum plaintext length, which is 2<sup>38</sup> bytes (256 GiB).
- `T_LEN`: the length of the authentication tag, which is 32 bytes.
- `C_MAX`: the maximum ciphertext length, which is `P_MAX` + `T_LEN` bytes.

## The ChaCha20-Poly1305-SIV Algorithm
ChaCha20-Poly1305-SIV can be broken down into the following steps:

1. **Subkey derivation**: derive independent subkeys from the key and nonce for Poly1305 and the tag computation/encryption.
2. **Tag computation**: compute a tag from the key, nonce, associated data, and plaintext. The key and nonce are incorporated via the subkey, whereas the associated data and plaintext are included via the Poly1305 tag.
3. **Encryption**: perform nonce extension using the subkey and part of the tag, with the derived key as the key and more of the tag as the nonce for encryption.

For decryption, steps 2 and 3 are reversed because computing the tag requires the plaintext.

### Encrypt
```
Encrypt(key, nonce, associatedData, plaintext)
```

Inputs:
- `key`: the encryption key, which **MUST** be `K_LEN` bytes long.
- `nonce`: the nonce, which **MUST** be `N_LEN` bytes long.
- `associatedData`: optional associated data to authenticate, which **MUST NOT** be greater than `A_MAX` bytes long.
- `plaintext`: the message to encrypt, which **MUST NOT** be greater than `P_MAX` bytes long.

Outputs:
- `ciphertext`: the encrypted message, which has the same length as the plaintext.
- `tag`: the authentication tag, which **MUST** be `T_LEN` bytes long.

These **MUST** either be returned separately as a `(ciphertext, tag)` tuple or concatenated together as `ciphertext || tag`.

Steps:
```
allZeros = ByteArray(64)
subkeys = ChaCha20(key, ReadLE32(nonce[0..4]), nonce[4..16], allZeros)

poly1305Tag = Poly1305(subkeys[0..32], associatedData, plaintext)

tag = ChaCha20(subkeys[32..64], ReadLE32(poly1305Tag[0..4]), poly1305Tag[4..16], allZeros)[0..32]

encKey = ChaCha20(subkeys[32..64], ReadLE32(tag[0..4]), tag[4..16], allZeros)[32..64]
ciphertext = ChaCha20(encKey, 0, tag[16..28], plaintext)

return ciphertext and tag
```

### Decrypt
```
Decrypt(key, nonce, associatedData, ciphertext, tag)
```

Inputs:
- `key`: the encryption key, which **MUST** be `K_LEN` bytes long.
- `nonce`: the nonce, which **MUST** be `N_LEN` bytes long.
- `associatedData`: optional associated data to authenticate, which **MUST NOT** be greater than `A_MAX` bytes long.
- `ciphertext`: the encrypted message, which **MUST NOT** be greater than `C_MAX` - `T_LEN` bytes long.
- `tag`: the authentication tag, which **MUST** be `T_LEN` bytes long.

Outputs:
- `plaintext`: the decrypted message, which has the same length as the ciphertext.

or

- `"tag verification failed" error`: an error if the authentication tag is invalid for the given inputs, with the decrypted message and incorrect authentication tag not returned/exposed to the user.

Steps:
```
allZeros = ByteArray(64)
subkeys = ChaCha20(key, ReadLE32(nonce[0..4]), nonce[4..16], allZeros)

encKey = ChaCha20(subkeys[32..64], ReadLE32(tag[0..4]), tag[4..16], allZeros)[32..64]
plaintext = ChaCha20(encKey, 0, tag[16..28], ciphertext)

poly1305Tag = Poly1305(subkeys[0..32], associatedData, plaintext)

computedTag = ChaCha20(subkeys[32..64], ReadLE32(poly1305Tag[0..4]), poly1305Tag[4..16], allZeros)[0..32]

if ConstantTimeEquals(tag, computedTag) == false
    Wipe(plaintext)
    Wipe(computedTag)
    return "tag verification failed" error
else
    return plaintext
```

## Security Considerations
### Usage Guidelines
Every key **MUST** be randomly chosen from a uniform distribution. For example, randomly generated using a cryptographically secure pseudorandom number generator (CSPRNG) or the output of a collision-resistant KDF.

The nonce **MAY** be public and predictable. It **SHOULD** be unique for every encryption with the same key. Whilst the algorithm is misuse-resistant, one **MUST NOT** deliberately reuse nonces with the same key outside the context of key wrapping. Misuse-resistance is merely a fail-safe and only protects you to an extent (security degrades with nonce reuse).

It is **RECOMMENDED** to either randomly generate nonces with a CSPRNG or to use a counter that gets incremented after each encryption. Random nonces can be used to encrypt 2<sup>48</sup> messages using the same key with negligible collision probability (2<sup>-32</sup>, aligning with [NIST guidance](https://csrc.nist.gov/pubs/sp/800/38/d/final)). However, significantly more random nonces can theoretically be tolerated due to the misuse-resistance. For example, see the [ChaCha20-Poly1305-PSIV](https://eprint.iacr.org/2025/222) analysis. But be aware of the paragraph below.

Reusing a nonce with the same key, associated data, and plaintext leaks that the same parameters were used for encryption. This can still cause a loss of confidentiality for some applications. However, authenticity is maintained.

The multi-user/multi-key security of an AEAD scheme can be improved via [nonce randomisation](https://eprint.iacr.org/2018/993). One can either derive the randomness from secret key material or randomly generate and publicly store the randomness. This randomness can be combined with a counter through concatenation/XOR, or the entire nonce can be random. However, the XOR approach specified by [NIST for Ascon-AEAD128](https://csrc.nist.gov/pubs/sp/800/232/ipd) and used in [Internet protocols](https://datatracker.ietf.org/doc/html/rfc8446#appendix-E.2) is not suitable for commitment and thus **MUST NOT** be used.

Values concatenated to form the associated data **MUST** be unambiguously encoded. For example, by ensuring they are all fixed-length, by [appending/prepending their lengths](https://soatok.blog/2021/07/30/canonicalization-attacks-against-macs-and-signatures/), or by using a [separation indicator](https://csrc.nist.gov/pubs/sp/800/108/r1/upd1/final). Appending rather than prepending means the lengths do not need to be known in advance.

To achieve context commitment, the associated data can be made uncontrollable to the attacker (e.g., always left empty), or the [Hash-then-Encrypt (HtE)](https://eprint.iacr.org/2022/268) transform can be used with a collision-resistant hash function or KDF (e.g., [BLAKE3](https://c2sp.org/BLAKE3)). The latter also allows one to extend the nonce (e.g., to 192 or 256 bits) by hashing a larger nonce and deriving a subnonce alongside the subkey (384 bits of output).

If two parties are interactively communicating, separate keys (known to both parties) can be derived and used in different directions to help avoid nonce reuse. For example, one for Alice encrypting to Bob and one for Bob encrypting to Alice. Alternatively, part of the nonce can be unique to each sender, combined with a shared counter incremented for each message.

When encrypting large plaintexts, it is advisable to break them into chunks (e.g., 16 KiB - 1 MiB), which is known as stream encryption. This has several benefits, like early detection of tampered ciphertexts, better security against forgery, and reduced memory usage. [CHAIN](https://eprint.iacr.org/2015/189) is one way of doing this with a misuse-resistant AEAD. However, note that stream encryption cannot provide equivalent misuse-resistance due to the [chosen-prefix/secret-suffix (CPSS) attack](https://eprint.iacr.org/2015/189), which aims to recover a secret portion of the plaintext. This is relevant if an attacker can control a portion of the plaintext before the secret value, even if the plaintext begins with a known/predictable, fixed value (e.g., a version number).

The length of the ciphertext (excluding the tag) is equal to the length of the plaintext. This can leak information about the message content and is unsuitable for creating encrypted blobs that are indistinguishable from random data (e.g., encrypted files with no readable headers). If this is a concern, one can [pad](https://en.wikipedia.org/wiki/Padding_(cryptography)#ISO/IEC_7816-4) the plaintext prior to encryption using a scheme like [PADMÉ](https://arxiv.org/abs/1806.03160) or [Covert padding](https://github.com/covert-encryption/covert/blob/main/docs/Specification.md#padding). This padding is then removed after successful decryption. Note that there are security/overhead differences between deterministic and randomised padding that are beyond the scope of this document.

### Implementation Guidelines
Tag verification **MUST** be done in constant time. Otherwise, a timing attack can be used to produce a MAC forgery.

If tag verification fails, the decrypted message and computed authentication tag **MUST NOT** be returned/exposed to the user.

If possible in your programming language, secret/sensitive values (like the above, subkeys, and the Poly1305 tag) **SHOULD** be zeroed from memory in a way that cannot be optimised away by the compiler before functions return.

Truncated tags **MUST NOT** be supported to maximise security.

It is **RECOMMENDED** to use a well-known, existing cryptographic library for implementation, as this will likely result in the best performance and security (e.g., against side-channel attacks). Otherwise, care **MUST** be taken to avoid [timing side-channels](https://datatracker.ietf.org/doc/html/rfc8439#section-4) and [other side-channels](https://ieeexplore.ieee.org/document/7927155) (if relevant).

In the context of key wrapping with a fixed (e.g., all-zero) nonce, one can cache the Poly1305 and tag subkeys for the same key. However, this is **NOT RECOMMENDED** for a general-purpose API to discourage nonce reuse.

### Security Guarantees
ChaCha20-Poly1305-SIV targets the same [security level](https://eprint.iacr.org/2023/085) as ChaCha20-Poly1305, namely 256-bit security against plaintext recovery and 103-bit security against forgery. The latter is an oversimplification, however, and depends on the [size and number of messages](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-aead-limits) sent by an adversary.

When the same parameters are not reused for encryption, the entire output is indistinguishable from random. When they are reused, this is not the case, as that is impossible with a deterministic algorithm. However, authenticity is provided in both scenarios.

Based on the [ChaCha20-Poly1305-PSIV](https://eprint.iacr.org/2025/222) analysis, security is lost when a user makes ~2<sup>35</sup> queries with the same nonce, assuming the largest possible plaintext and associated data lengths (512 GiB).

The 256-bit tag [should](https://eprint.iacr.org/2025/222) provide 128-bit key-committing security ([CMT-1](https://eprint.iacr.org/2022/268)/[CMTk](https://eprint.iacr.org/2023/526)) due to the birthday bound. We also hypothesise CMT-2/CMTn security, but this has not been studied sufficiently. The subkey is a [commitment](https://www.usenix.org/conference/usenixsecurity22/presentation/albertini) of the key and nonce, and the tag is a [commitment](https://tosc.iacr.org/index.php/ToSC/article/view/11296) of the subkey and Poly1305 tag, meaning the tag also commits to the key and nonce. This can be viewed like the [padding fix](https://www.usenix.org/conference/usenixsecurity22/presentation/albertini) in place of [HtE](https://eprint.iacr.org/2022/268) plus [CTX](https://eprint.iacr.org/2022/1260) minus the associated data processing, meaning there is no context commitment (CMT-3).

To expand on the above, the untruncated ChaCha20 permutation [cannot](https://eprint.iacr.org/2023/085) have collisions because a permutation is a 1-1 mapping. Then the ChaCha20 block function applies a feed-forward (Davies-Meyer with addition), which provides collision resistance [without truncation](https://eprint.iacr.org/2022/268) and [with truncation](https://eprint.iacr.org/2025/222) assuming the ChaCha20 permutation is ideal, as done in security analyses. Furthermore, without the feed-forward but truncation, as in HChaCha20, there should [still](https://link.springer.com/chapter/10.1007/978-3-642-03317-9_7) [be](https://link.springer.com/chapter/10.1007/978-3-030-34578-5_7) [collision resistance](https://eprint.iacr.org/2022/508) given the ChaCha20 state contains a 128-bit constant (1/4 of the state) that cannot be attacker-controlled.

Because the scheme uses a [preimage resistant MAC](https://eprint.iacr.org/2024/928) (truncated Davies-Meyer), there is context discoverability security ([CDY](https://eprint.iacr.org/2023/526)).

The mitigation for context unforgeability security ([CFY](https://eprint.iacr.org/2024/733)) is unclear. If we focus on the key/nonce, key commitment implies CFY security, and this paper claims ChaCha20-Poly1305 is CFY secure despite it not being key committing. However, if we include the associated data, ChaCha20-Poly1305 is likely not secure, and our scheme lacks context commitment. On the other hand, a CDY attack (often) implies a CFY attack, but our scheme is not vulnerable to CDY attacks. Additionally, we hypothesise that an attacker cannot efficiently find a different associated data given that the Poly1305 tag cannot be retrieved (since it is masked) or recomputed (since the plaintext is unknown). Therefore, we predict full CFY security, but this whole notion needs more study.

SIV [provides](https://tosc.iacr.org/index.php/ToSC/article/view/8697) integrity under the release of unverified plaintext ([INT-RUP](https://eprint.iacr.org/2014/144)) and plaintext awareness 1 (PA1) for confidentiality, which is weaker than PA2. This means forgery is not possible, but the decryption of other messages may be. ChaCha20-Poly1305 also [provides](https://eprint.iacr.org/2016/1124) INT-RUP, but this paper additionally shows how a fixed point with Poly1305 allows an INT-RUP attack with no nonce. Therefore, this scheme lacks INT-RUP security when a nonce is reused.

When the `r` part of the `(r, s)` Poly1305 key is all-zero ([a weak key](https://datatracker.ietf.org/doc/html/rfc8439#appendix-A.3)), the tag becomes equal to `s` regardless of the processed message. However, the probability of this happening with the specified key derivation technique is extremely unlikely, as in ChaCha20-Poly1305.

A formal security analysis is left as future work.

## Design Rationale
### Design Goals
The following goals were used when developing this scheme:

- **Nonce misuse-resistance**: the tag must depend on the key, nonce, associated data, and plaintext. Then encryption must depend on either (part of) the tag or the nonce and tag.
- **Key commitment**: the tag must be collision resistant and a commitment of the key (and ideally, the nonce too). This still allows context commitment through the key parameter.
- **Context discoverability secure**: the tag must be preimage resistant (one-way).
- **Performant**: performance should be as close to (X)ChaCha20-Poly1305 as possible. Anything significantly slower is unlikely to get used.
- **Existing APIs**: the algorithm should be possible to implement using existing cryptographic library APIs. There should also be compatibility with as many existing APIs as possible. This considerably improves the potential speed and likelihood of adoption.
- **Simplicity**: the design should be intuitive, familiar, and easy to implement. This reduces mistakes, increases adoption, and aids analysis. For example, the Poly1305 inputs can be processed the same way as in ChaCha20-Poly1305. Ideally, only ChaCha20 and Poly1305 should be used due to their wider availability than HChaCha20 and ChaCha8/ChaCha12.
- **Security analyses**: the design should be based on existing security analyses of ChaCha20/Poly1305. The ChaCha20 state (e.g., constants) should not be modified if possible so security analyses maximally apply. There should also be a comfortable security margin (e.g., ChaCha8 should be avoided).
- **Not worried about fancy features**: for example, nonce hiding, key caching/pre-processing static associated data, the best possible security against the release of unverified plaintext, etc. These types of features do not align with existing AEAD schemes, complicate a design, and generally worsen performance.
- **No variants**: there should not be separate key, nonce, tag, or counter sizes. Variants mean user confusion, worse interoperability, more implementation/documentation burden, etc.

Note that some of these goals limit performance and security. For example, using two Poly1305 instances, like in ChaCha-Daence, improves the security level but harms performance compared to ChaCha20-Poly1305.

### Larger Nonce
A 96-bit nonce is [too small](https://soatok.blog/2024/07/01/blowing-out-the-candles-on-the-birthday-bound/) to randomly generate without frequently rotating the key. More random nonces can be [tolerated](https://eprint.iacr.org/2025/222) with a misuse-resistant scheme, but there can be security implications due to the deterministic encryption when all the parameters are repeated. Thus, a larger nonce is sensible.

Replicating [XChaCha20](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha) would work but incurs some performance overhead, increases the size of the key derivation cascade, and possibly introduces another primitive. In contrast, utilising the counter portion of the state is virtually free (converting bytes to an integer).

If adjusting the counter produced identical keystream outputs, ChaCha20 would not be a secure stream cipher. Furthermore, HChaCha20 does the same but with truncation instead of the feed-forward.

### Key Derivation
Poly1305 needs its own key, the nonce needs to be incorporated into the tag computation, and it is best practice to use different keys for different purposes.

The key derivation in ChaCha20-Poly1305 leaves 256 bits [unused](https://datatracker.ietf.org/doc/html/rfc8439#section-2.6), meaning you can get a second key for free. That covers both tag computations.

To obtain a third key for encryption, another ChaCha20 block could be output. However, this worsens performance and could cause the counter to overflow, which can lead to errors/exceptions in existing APIs.

This counter overflow checking is also problematic for using the tag as the nonce plus counter during encryption. Therefore, nonce extension like in XChaCha20 can be used.

As this results in a new key, it is unnecessary to derive another key just for the nonce extension as long as there is domain separation. Taking a different part of the output from the tag computation achieves this, even if the ChaCha20 inputs for tag computation and nonce extension are identical.

### Domain Separation
With a pseudorandom function (PRF), domain separation can be achieved by using a different key and/or message or by using different parts of the output.

The above section explains that different keys and parts of the output are used. The user's nonce, the Poly1305 tag, and the final tag are also likely to be different because each one influences the next.

While it would be ideal to provide separate counters for each ChaCha20 call so the initial state cannot collide, this is not possible when processing the full Poly1305 tag and would require reducing the nonce and nonce extension size. Alternatively, the key size could potentially be reduced.

For the tag to be equivalent to part of a keystream block used during another encryption call, the initial state would need to match or there would need to be an output collision.

Then the key derivation/nonce extension calls produce secret, internal values, so a collision with a keystream block used for encryption does not matter.

### Commitment
There is [debate](https://eprint.iacr.org/2025/377) among cryptographers as to whether 64-bit committing security is [sufficient](https://www.usenix.org/conference/usenixsecurity22/presentation/albertini). However, commitment is related to [collision resistance](https://eprint.iacr.org/2023/526) and an [offline attack](https://eprint.iacr.org/2024/875). Few people would argue a 64-bit security level is collision resistant since that is an [achievable attack](https://eprint.iacr.org/2019/1492), with collision-resistant hash functions targeting at least 112-bit collision resistance. Furthermore, as a designer, you do not know how the algorithm will be used, so you must assume the worst (e.g., long-lived ciphertexts).

Obtaining good committing security requires using a larger tag due to the birthday bound. This larger tag can be condensed into a 120-bit tag with 112-bit collision resistance (or more if operating on bits) via the [succinctly-committing](https://eprint.iacr.org/2024/875) approach. However, this is less efficient, more complicated to implement, not trivial to understand, and still inflates the ciphertext expansion and has weak security for very small messages.

In terms of tag length, [Chan and Rogaway](https://eprint.iacr.org/2022/1260) have suggested a minimum of 160 bits for 80-bit committing security, which [Bellare and Hoang](https://eprint.iacr.org/2024/875) seem to agree is strong enough. But this is an atypical tag size, still a weak security level, and short for nonce extension (e.g., it requires padding). 192 and 224 bits are also odd sizes, and you may as well go to 256 bits at that point for a 128-bit security level.

## Test Vectors
These test vectors are for two types of tests:

1. Successful encryption and decryption.
2. Unsuccessful decryption when each parameter is individually tampered with.

In the latter case, one **MUST** check that an error is returned and that the plaintext is not returned.

### Test Vector 1
```
key: 1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2

nonce: 530ee5e3dae7693017d28e5d7c6936ce

associatedData:

plaintext:

ciphertext:

tag: 85ebd6b3a2dbad07d4811283aaf9777acff58bdab40939a13237be73d3ddd73a
```

### Test Vector 2
```
key: 1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2

nonce: 530ee5e3dae7693017d28e5d7c6936ce

associatedData:

plaintext: 4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e

ciphertext: 935fc3675f8b409d4441409418d92f7d7f52af0a00adc07176c998dbdfaa4d06524ea0769635e044a6aaf00327096437613bec8c76eea651dcaccc2fc66087bda224f38ab220208a9471a3e9eec612c2553d8179f1bd1bf7e884fa25336e5f19ef46bb3581245603969b1b11293ad5611608

tag: cb0ff82acbd025c9db100311c6628f41ad9ba81a960b8ccd7fdb19c51252e902
```

### Test Vector 3
```
key: 1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2

nonce: 85975d0ee263b966a551adab8325ebe3

associatedData:

plaintext: 4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e

ciphertext: 00abda8eb9d81e4bbfec468c33175102ca865a9e10bd1af861a205a996c9818993bd0f5957a0a163a1585bf469ca154802b300c78dd873c9a67111d7eeb3b9d3ee7e7ad37db8375ba30031afaaab163057418225f403b4cbdd0cd3dc4024b984462802ec7fb87bd91ff548a13db805695fa9

tag: 4417acff4230861c1ee555cc839fe8b9ccb122fda85b3970d677dc71e8515276
```

### Test Vector 4
```
key: 3ef4832df6f83cd761539792c7c34b90fde64ca02d31151fdf924bf2206e37cb

nonce: 530ee5e3dae7693017d28e5d7c6936ce

associatedData:

plaintext: 4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e

ciphertext: b00fea62ad4a7d06b99ce816e2800bb51ac0a7ad39a216a1131eb23efd2771f824df9ea5773d68d26a83e04a00e81587cf68353157e5b1abd2a99d9d8c50557ae3c6dfcbad6ad1ccee167c24cb049cf11221ffe1f63231efedf89c3e31c549df66281722670ad82a5014b7fa3869f91a9ccc

tag: 1d54d3476529356000f20919ac9de59d8ed4f39a62225bc689822916b748cab0
```

### Test Vector 5
```
key: 1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2

nonce: 530ee5e3dae7693017d28e5d7c6936ce

associatedData: 50515253c0c1c2c3c4c5c6c7

plaintext: 4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e

ciphertext: 65047ab0ada975747e1a1737abd6cb0aeb126b8e8f974c6dc0a45e091a4992ad1190080ab2acc2a5a62c9fff72466f7e054d2b4e9474f01d5b200cc6788e0e30351842fc058faee14fe97fe7cee8d0c84e64fa1b55c19e658468d6035376616182d6d09e3066e9318134e4e2bfadfd381256

tag: e85b5e838e89c84d2f544f40cd65bcccfe6f4438ed6325a06d301881ec2e90d2
```

### Test Vector 6
```
key: 1a1ea9537ef6e0587ac4d36d4c73e07b1526e18bf5bb008f63e4a49b2178a8d2

nonce: 530ee5e3dae7693017d28e5d7c6936ce

associatedData: 2891ec111a27c55b3a6757ff173ef9cfc02bb682bcee4aaa317715b0b7895a58

plaintext: aeadc48d4a2ea7ee06f9f41a6fbcd651ac5df158860e14af1fb0ebbe0a04bab2

ciphertext: 10287f0d994ca8b920dcede7ce86a29a055ac8e1c0ca14fe651bb363a2af7e03

tag: 9283515c1a67bf9234494025356684abae8325ad5a2f7ce275ac7fa49d88d735
```

## Acknowledgements
ChaCha20 and Poly1305 were designed by Daniel J. Bernstein before being combined to form ChaCha20-Poly1305 by Adam Langley and Yoav Nir.

HChaCha20, XChaCha20, and XChaCha20-Poly1305 were specified by Scott Arciszewski, with HSalsa20 and XSalsa20 being designed by Daniel J. Bernstein.

SIV was proposed by Phillip Rogaway and Thomas Shrimpton.

Thank you to the authors of all the algorithms and constructions referenced in this document. Our design was heavily inspired and motivated by such prior work.

Thank you to Loup Vaillant for the idea to use the second half of the Poly1305 key derivation block as a commitment string (an optimised version of the padding fix) and for discussion about key derivation with HChaCha20 vs ChaCha20.

Thank you to Yu Long Chen, Sanketh Menda, and Zhongtang Luo for answering some questions related to CMT, CDY, and CFY security.
