# Post-Quantum Algorithms for HTTP Message Signatures

[c2sp.org/httpsig-pq](https://c2sp.org/httpsig-pq)

- **Version**: v1.0.0
- **Authors**:
  - [Soatok Dreamseeker](https://github.com/soatok)

## Introduction

This document specifies three HTTP Message Signature algorithm identifiers for the ML-DSA signature schemes standardized
in FIPS 204. The identifiers are defined for the `alg` signature parameter and the HTTP Signature Algorithms registry
created by RFC 9421.

HTTP Message Signatures, including signature base construction, the `Signature-Input` field, the `Signature` field, and
application-level verification requirements, are specified by RFC 9421. This document defines the complete mapping
between the byte-oriented `HTTP_SIGN` and `HTTP_VERIFY` primitives in RFC 9421 and ML-DSA.

## Normative references

This document normatively references the following fixed publications:

- [BCP 14, Key Words for Use in RFCs to Indicate Requirement Levels](https://www.rfc-editor.org/info/bcp14), comprising
  RFC 2119 and RFC 8174.
- [RFC 4648, The Base16, Base32, and Base64 Data Encodings](https://www.rfc-editor.org/rfc/rfc4648.html), especially
  Section 4.
- [RFC 9421, HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421.html), especially Sections 2.5, 3.1,
  3.2, 4.2, and 6.2.
- [FIPS 204, Module-Lattice-Based Digital Signature Standard, published August 13, 2024](https://doi.org/10.6028/NIST.FIPS.204),
  especially Section 3.6, Table 2, Algorithms 1, 2, 3, 6, and 13, and the key and signature encodings in Section 7.2 
  (Algorithms 22 through 27).

In this document, “FIPS 204” means that specific August 13, 2024 publication. A later revision, successor, or 
technically changed erratum is not automatically incorporated into these algorithm identifiers. Any incompatible change
to an identifier defined here requires a new HTTP Signature Algorithms registry identifier.

## Conventions

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",
"NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in
[BCP 14](https://www.rfc-editor.org/info/bcp14) when, and only when, they appear in all capitals.

An octet is an 8-bit byte. `len(X)` denotes the length of byte string `X` in octets. `empty` denotes the zero-length
byte string. Base64 is the standard Base 64 encoding in [RFC 4648, Section 4](https://www.rfc-editor.org/rfc/rfc4648.html#section-4),
including padding and without whitespace unless the containing protocol states otherwise.

## Algorithms

The following values are defined for the RFC 9421 `alg` signature parameter:

| `alg` value | FIPS 204 parameter set | Signing key `Ks` | Public key `Kv` | Signature `S` |
|-------------|------------------------|-----------------:|----------------:|--------------:|
| `ml-dsa-44` | ML-DSA-44              |        32 octets |     1312 octets |   2420 octets |
| `ml-dsa-65` | ML-DSA-65              |        32 octets |     1952 octets |   3309 octets |
| `ml-dsa-87` | ML-DSA-87              |        32 octets |     2592 octets |   4627 octets |

The `Ks`, `Kv`, and `S` columns describe the values at the `HTTP_SIGN` and `HTTP_VERIFY` algorithm boundary. In 
particular, the `Ks` size is the seed representation defined below, not the size of the expanded `skEncode` value
reported as a private key by FIPS 204 Table 2.

Each `alg` value is an indivisible identifier for exactly the parameter set and operations defined below.
Implementations MUST compare the complete identifier and MUST NOT construct or infer other algorithm identifiers by 
parsing its components. When carried in the RFC 9421 `alg` signature parameter, the identifier is a Structured Fields
String value; for example, `ml-dsa-44` is serialized as `;alg="ml-dsa-44"`. Identifiers are case-sensitive, and no other
spelling identifies an algorithm defined by this document.

### Key material

For all three algorithms, the signing key material `Ks` is exactly the 32-octet seed `ξ` generated in line 1 of
`ML-DSA.KeyGen` in FIPS 204 Algorithm 1. The public verification key `Kv` is the `pk` output obtained by applying
`ML-DSA.KeyGen_internal` in Algorithm 6 for the selected parameter set:

```text
(Kv, sk) = ML-DSA.KeyGen_internal(Ks)
```

`Kv` is exactly the `pkEncode(ρ, t1)` byte string defined by FIPS 204 Algorithm 22. The value `sk` is the expanded
`skEncode(ρ, K, tr, s1, s2, t0)` byte string defined by FIPS 204 Algorithm 24 and used as the input to FIPS 204
Algorithm 2. In this document, `sk` is a derived, implementation-internal representation of `Ks`; it is not an
alternative encoding of `Ks`.

Implementations MUST accept only the 32-octet `Ks` representation at the algorithm boundary defined here and MUST NOT
accept the 2560-, 4032-, or 4896-octet `skEncode` output in its place. An implementation MAY retain `sk` or any other
expanded representation in memory after processing `Ks`, but no expanded private-key serialization is defined by this
document.

A new `Ks` MUST be generated as a fresh 32-octet random value with the approved random bit generator and security
strength required for `ξ` by FIPS 204 Section 3.6.1. The parameter set is not encoded in `Ks`; applications MUST bind
each `Ks` to exactly one of the three complete algorithm identifiers. Although Algorithm 6 incorporates the selected
parameter set into key expansion, trying the same `Ks` under multiple parameter sets is not a key-selection mechanism.

This document does not define a certificate, SubjectPublicKeyInfo, JWK, COSE_Key, PKCS #8, key identifier, discovery
protocol, or other key container. Applications that use such mechanisms MUST recover the 32-octet `Ks` or the
`pkEncode` value `Kv`, together with its parameter-set binding, before applying this algorithm.

### Mapping the signature base to ML-DSA

For both signing and verification, `M` is the ordered byte sequence returned by the signature base creation algorithm
in RFC 9421 Section 2.5. RFC 9421 requires that sequence to be ASCII. Implementations MUST pass those bytes unchanged:
they MUST NOT append a newline, convert LF to CRLF, re-encode the text, prehash it, or add framing.

Write the octets of `M` as `M[0]` through `M[len(M)-1]`. FIPS 204 Algorithms 2 and 3 take a bit string as their message
input. That bit string is `BytesToBits(M)` from FIPS 204 Algorithm 13: for every `i` and for `j` from 0 through 7, bit
`8i+j` is `(floor(M[i] / 2^j) mod 2)`. This is little-endian bit order within each octet. An ML-DSA API whose message
input is a byte string MUST be given `M` directly; the byte-oriented API performs this conversion.

The ML-DSA context `ctx` is the zero-length byte string `empty`. Consequently, line 10 of FIPS 204 Algorithm 2 and line
5 of Algorithm 3 form their internal message as `BytesToBits(0x00 || 0x00 || M)`. The two `0x00` octets are added by
`ML-DSA.Sign` and `ML-DSA.Verify`; callers MUST NOT prepend them to `M`.

### `HTTP_SIGN`

For a selected identifier, `HTTP_SIGN(M, Ks)` returns a signature byte string `S` or an error:

1. If `len(Ks)` is not 32 or `Ks` is bound to another parameter set, return an error and no signature.
2. Obtain `(Kv, sk)` by applying `ML-DSA.KeyGen_internal(Ks)` from FIPS 204 Algorithm 6 for the selected parameter set.
   An implementation MAY reuse values previously derived from the same `Ks` for that parameter set. This expansion or
   retrieval occurs inside the implementation; `sk` is not an additional input to `HTTP_SIGN`.
3. Invoke `ML-DSA.Sign(sk, BytesToBits(M), empty)` as specified by FIPS 204 Algorithm 2.
4. If key derivation or retrieval, random generation, or signing fails, return an error and no signature. Otherwise,
   let `S` be the Algorithm 2 output `σ`. `S` is exactly the `sigEncode(c_tilde, z, h)` byte string defined by FIPS 204
   Algorithm 26 and has the length in the table above.

FIPS 204 permits hedged and deterministic variants of Algorithm 2. Signers MAY implement either variant, and
verifiers MUST accept valid signatures from both. Signers SHOULD use the default hedged variant for production. In the
deterministic variant, the internal `rnd` value is 32 zero octets as specified by FIPS 204; `rnd` is not an additional
input to `HTTP_SIGN`.

### `HTTP_VERIFY`

For a selected identifier, `HTTP_VERIFY(M, Kv, S)` returns a Boolean:

1. If `Kv` is bound to another parameter set or `len(Kv)` does not equal the public-key size in the table above for the
   selected identifier, return `false`.
2. If `len(S)` does not equal the signature size in the table above for the selected identifier, return `false`.
3. Invoke `ML-DSA.Verify(Kv, BytesToBits(M), S, empty)` as specified by FIPS 204 Algorithm 3.
4. Return `true` only if Algorithm 3 returns `true`. Return `false` for every other result, including a decoding error,
   a malformed signature, or any other verification failure.

The signature output `S` is inserted as the RFC 9421 `Signature` field's Byte Sequence value. It is not DER encoded,
wrapped in ASN.1, prefixed with an algorithm identifier or length, or otherwise transformed before insertion. The
Structured Fields serialization of a Byte Sequence uses Base64 to transport `S`; that Base64 text is not the output of
`HTTP_SIGN` and is not the input to `HTTP_VERIFY`. For a signature labeled `sig1`, the field is serialized as
`Signature: sig1=:<Base64(S)>:`; the two colon characters delimit the Byte Sequence and are not part of `S`.

HashML-DSA, application-level prehashing, external message-representative (`mu`) processing, non-empty ML-DSA contexts,
and any other representation of `M` are not defined for these identifiers and MUST NOT be used.

An implementation MAY realize these operations using `ML-DSA.Sign_internal`, `ML-DSA.Verify_internal`, or another
mathematically equivalent procedure, provided its observable behavior is equivalent to the specified calls to
`ML-DSA.Sign` and `ML-DSA.Verify`. This equivalence includes construction of the formatted message `M'` from
`BytesToBits(M)` and `empty`, handling of `rnd`, encoding of `S`, and the set of inputs for which verification returns
`true`.

### Algorithm binding

The algorithm selected by an application, the complete `alg` value when present, and the parameter set associated
with the key material MUST agree. A verifier MUST apply the algorithm-selection and consistency checks in RFC 9421
Section 3.2, including failing verification when algorithms selected from different sources disagree. The `alg`
parameter remains optional as specified by RFC 9421; an application can select one of these algorithms through trusted
configuration or other external information without sending the parameter.

## Test vectors

The machine-readable test vectors at the end of this document are part of this versioned specification. They contain
one deterministic signing and verification vector for each identifier, including the 32-octet key-generation seed
`ξ`, the `pkEncode` output, the signature-base octets, a SHA-256 checksum of those octets, the serialized
`Signature-Input` field, and the `sigEncode` output.

For each vector, `private_key_seed_hex` is the lowercase hexadecimal encoding of the 32-octet `ξ` input to FIPS 204
Algorithm 6. `public_key_base64`, `signature_base_base64`, and `deterministic_signature_base64` are padded RFC 4648
Base64 encodings without whitespace. They decode to `pk`, `M`, and `S`, respectively. The seed is supplied solely to
make `(pk, sk)` and the deterministic signature reproducible; it is not substituted for `sk` as the input to FIPS 204
Algorithm 2.

The `signature_base_base64` member is the unambiguous representation of the bytes passed to `HTTP_SIGN` and
`HTTP_VERIFY`. Each decoded signature base is 252 ASCII octets, uses a single LF octet (`0x0a`) between adjacent lines,
and has no terminal newline. The displayed code blocks below have a presentation newline before the closing fence;
that presentation newline is not part of the signature base.

The signatures use the deterministic FIPS 204 signing variant with the internal `rnd` value set to 32 zero octets.
Production hedged signatures will generally differ and are equally valid.

### ML-DSA-44

```text
"@method": GET
"@target-uri": https://example.com/foo?param=Value&Pet=dog
"host": example.com
"date": Mon, 06 Jul 2026 20:00:00 GMT
"@signature-params": ("@method" "@target-uri" "host" "date");created=1783368000;keyid="test-key-mldsa44";alg="ml-dsa-44"
```

SHA-256 of the signature base:
`08264481b48366f88f467c5af283f501ebb2a18ddf08dc19fa422f1f985a79e8`.

### ML-DSA-65

```text
"@method": GET
"@target-uri": https://example.com/foo?param=Value&Pet=dog
"host": example.com
"date": Mon, 06 Jul 2026 20:00:00 GMT
"@signature-params": ("@method" "@target-uri" "host" "date");created=1783368000;keyid="test-key-mldsa65";alg="ml-dsa-65"
```

SHA-256 of the signature base:
`16bcacd62d4a02f3b91e6a412c27d1778ab08fcc7617a8db5f3f035f268239d0`.

### ML-DSA-87

```text
"@method": GET
"@target-uri": https://example.com/foo?param=Value&Pet=dog
"host": example.com
"date": Mon, 06 Jul 2026 20:00:00 GMT
"@signature-params": ("@method" "@target-uri" "host" "date");created=1783368000;keyid="test-key-mldsa87";alg="ml-dsa-87"
```

SHA-256 of the signature base:
`95cdd4d08ea1f138fbd922ebb1da856744048ea66bb5906a118ce8c15e5436e5`.

### Negative tests

For every vector, a verifier MUST return `false` after any of the following changes while retaining the vector's
signature:

- Change any covered component value, remove a covered component line, change an LF to CRLF, or append a terminal LF.
- Substitute another `alg` value in the `@signature-params` line.
- Use another public key, including another key from the same parameter set.
- Flip a signature bit, remove a signature octet, or append a signature octet.
- Use a public key or signature whose length differs from the selected parameter set's required length.
- Invoke ML-DSA verification with a non-empty context or with a digest of the signature base instead of the signature
  base itself.

### Machine-readable test vectors

The following JSON object is the machine-readable form of the test vectors specified above.

```json
{
  "version": 1,
  "description": "Deterministic conformance vectors for Post-Quantum Algorithms for HTTP Message Signatures v1.0.0",
  "vectors": [
    {
      "id": "ml-dsa-44-deterministic",
      "algorithm": "ml-dsa-44",
      "private_key_seed_hex": "c80d699b2daa47d54b8697f5a917c696400d7063b30a234d18ad672250ae42d9",
      "public_key_base64": "guWbbXQe/Y1a83/qIeU8MjIrRseICPuOyWzoGXk27Fia2lpk2uPxbEfh/iEmvY1z/LTtxSBFZS8zbgV04qa038ZokwE+QoBcISX0H4F9hEY3Oxg8SRtzrek0E+mBOc6R4ilBje5vodImgSMTMSXKuDz2PWqvrLY20AfLmMkLXZqVERYcW+S7iKyTP53cvtenYwealt3MGcZxLKRAMnCGBY3pRfj1xn6czY6OuMYNuJaW1rAeL2BeVpNA+XBA+HUHS1yTYOGw93ddFe9lw0RDex7Pw+tht/n31gggrR4D0kmE8L88Q5c2qWuQtxk9+cmHTm3u1WuG/vCRiubTA3DmY0pK1fO1etarscNRnZ06q5UfTgSQOMqR/PLXtqT9cZiN8GWQvum15uVuxXCubB4r7T3nz2ijyBPQfo+Ywd10QxI8dpGpsBd9SEslLo+esyFDt7+9t4c702PNC0121oI18PriNlKxjxshQljNnrXSZ4eCvhHrY5Le8B/mTwsb/LYPbBvktCecvkRxboTjhyq2anblDt5Hp55gn+0YRWUz7myuDjBD/+a2riHzOXCoLOtGvsfVTLAwLPYj/AIBbdVFrGq9MKldtcgiqTWhG6JWD/dxFrfUT4YIf2yWO9AbhkgkgPynKmV82sLda4L3JaABwSXVAB1vzDmxfQ17orBFxX2pK23G5EmrG8Ix/1O9NJ35LSxkZhUmNs+4zm9GRaChPbw04q//Gc9CPiE3xvv/BrRms5mIiRl7zT8o2mgNs/APM45mJrKClmYRQllKVwnKBj+njZkDv1CG2WeBv01COmic4P4EEraSmKO8I5sJ98gpTiA9jeBuvloLYdAInPyZui01GyQO4P3OETyAVqggBGIvajxWuio7eL+4XZmkX3AMb5XrfWtlfYCKUzhodcv7NM6M4LizEh0KZ8qSHsnVZxqwb5J9hb4oiR5/N7sgxjjtiBsbg/vJ1UmBZZR6hPjnLbLDTZ6PUMjeQNdoYGL0Cv4ESloaEtc4vhW/Aa2roIyoAM/kimrHYztNknxZK3nLQ9PXVp9Np1okp4VPUkOfHvy6Bk2WPQd8vdwrfE3xOPGrkhzdmlcsVEp3rIAW4s4Hem2A99CFSkbPePEEPG4uB3sVl73X+sr8+X7jFkiiy686eV73zQTrqL4OnrYJIkaZr6zLXHccvm1txmftmtS3WH3Ny0hGVjwxnu1femv2++2pZpZr67//WBksxPOG4xk6AA7xrHEAjRFA0b0g6AC3+WuZmaNCNMd8YdibEt/WHKg7uGWYetMf45cWxPxZmNl+jddlf1btTAfYZ+eXla3Tx/pg5fU2EWTXyTOVIRdRwAOpZHG7jFYCxRE2SWFFM2lwjLxzso69uABhM1zraUxo6TfOalw1x7S1NkTowesaJPlTMmr43N5hdbRyDD6qmcCSNNjDICvK/fv3ijSY0lueglt1Jf7O1fi9/s0CNGf8E/pQohdb/pzGhSlJRo73hC/wTmLEjFukAYNdNeJO8Fxge7j6rLHIOu22q8lK0DSsWqXXeFYt5mKmdTOFHN6soJQ7Uk43HgwoMreCn6xJQhl87CZu4SUzr5XztrsOV/YF5u5IYY8cDneoZW+0ldE+/8bvI8gi352YmfL9ZY5TacDexbl0S+hGbR7IPHh6av0N+odj2uBNt4Cjb3Mt3aYwQi2Yh9vD+CaGcz5AO67GAf7pIpS8naBrzQeNjdOYLxu6VcXT4zLO9Gu1Uv+RvkLPaalcAQ==",
      "signature_base_base64": "IkBtZXRob2QiOiBHRVQKIkB0YXJnZXQtdXJpIjogaHR0cHM6Ly9leGFtcGxlLmNvbS9mb28/cGFyYW09VmFsdWUmUGV0PWRvZwoiaG9zdCI6IGV4YW1wbGUuY29tCiJkYXRlIjogTW9uLCAwNiBKdWwgMjAyNiAyMDowMDowMCBHTVQKIkBzaWduYXR1cmUtcGFyYW1zIjogKCJAbWV0aG9kIiAiQHRhcmdldC11cmkiICJob3N0IiAiZGF0ZSIpO2NyZWF0ZWQ9MTc4MzM2ODAwMDtrZXlpZD0idGVzdC1rZXktbWxkc2E0NCI7YWxnPSJtbC1kc2EtNDQi",
      "signature_base_length": 252,
      "signature_base_sha256": "08264481b48366f88f467c5af283f501ebb2a18ddf08dc19fa422f1f985a79e8",
      "serialized_signature_input": "Signature-Input: sig1=(\"@method\" \"@target-uri\" \"host\" \"date\");created=1783368000;keyid=\"test-key-mldsa44\";alg=\"ml-dsa-44\"",
      "deterministic_signature_base64": "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"
    },
    {
      "id": "ml-dsa-65-deterministic",
      "algorithm": "ml-dsa-65",
      "private_key_seed_hex": "40342eccce31032955f04c14256fa8cb6b6269bdc22d6ee62fd00d9338759773",
      "public_key_base64": "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",
      "signature_base_base64": "IkBtZXRob2QiOiBHRVQKIkB0YXJnZXQtdXJpIjogaHR0cHM6Ly9leGFtcGxlLmNvbS9mb28/cGFyYW09VmFsdWUmUGV0PWRvZwoiaG9zdCI6IGV4YW1wbGUuY29tCiJkYXRlIjogTW9uLCAwNiBKdWwgMjAyNiAyMDowMDowMCBHTVQKIkBzaWduYXR1cmUtcGFyYW1zIjogKCJAbWV0aG9kIiAiQHRhcmdldC11cmkiICJob3N0IiAiZGF0ZSIpO2NyZWF0ZWQ9MTc4MzM2ODAwMDtrZXlpZD0idGVzdC1rZXktbWxkc2E2NSI7YWxnPSJtbC1kc2EtNjUi",
      "signature_base_length": 252,
      "signature_base_sha256": "16bcacd62d4a02f3b91e6a412c27d1778ab08fcc7617a8db5f3f035f268239d0",
      "serialized_signature_input": "Signature-Input: sig1=(\"@method\" \"@target-uri\" \"host\" \"date\");created=1783368000;keyid=\"test-key-mldsa65\";alg=\"ml-dsa-65\"",
      "deterministic_signature_base64": "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"
    },
    {
      "id": "ml-dsa-87-deterministic",
      "algorithm": "ml-dsa-87",
      "private_key_seed_hex": "0cd2f7cc3f9772ad23031ef37aea63b3825fb46bdb5d5cc4fb620ecccc5e630b",
      "public_key_base64": "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",
      "signature_base_base64": "IkBtZXRob2QiOiBHRVQKIkB0YXJnZXQtdXJpIjogaHR0cHM6Ly9leGFtcGxlLmNvbS9mb28/cGFyYW09VmFsdWUmUGV0PWRvZwoiaG9zdCI6IGV4YW1wbGUuY29tCiJkYXRlIjogTW9uLCAwNiBKdWwgMjAyNiAyMDowMDowMCBHTVQKIkBzaWduYXR1cmUtcGFyYW1zIjogKCJAbWV0aG9kIiAiQHRhcmdldC11cmkiICJob3N0IiAiZGF0ZSIpO2NyZWF0ZWQ9MTc4MzM2ODAwMDtrZXlpZD0idGVzdC1rZXktbWxkc2E4NyI7YWxnPSJtbC1kc2EtODci",
      "signature_base_length": 252,
      "signature_base_sha256": "95cdd4d08ea1f138fbd922ebb1da856744048ea66bb5906a118ce8c15e5436e5",
      "serialized_signature_input": "Signature-Input: sig1=(\"@method\" \"@target-uri\" \"host\" \"date\");created=1783368000;keyid=\"test-key-mldsa87\";alg=\"ml-dsa-87\"",
      "deterministic_signature_base64": "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"
    }
  ]
}
```

## IANA considerations

This document defines the following entries in the HTTP Signature Algorithms registry. The reference is the immutable
version of this specification and its algorithm definitions.

| Algorithm Name | Description              | Status | Reference                                                                                      |
|----------------|--------------------------|--------|------------------------------------------------------------------------------------------------|
| `ml-dsa-44`    | ML-DSA-44 using FIPS 204 | Active | [https://c2sp.org/httpsig-pq@v1.0.0#algorithms](https://c2sp.org/httpsig-pq@v1.0.0#algorithms) |
| `ml-dsa-65`    | ML-DSA-65 using FIPS 204 | Active | [https://c2sp.org/httpsig-pq@v1.0.0#algorithms](https://c2sp.org/httpsig-pq@v1.0.0#algorithms) |
| `ml-dsa-87`    | ML-DSA-87 using FIPS 204 | Active | [https://c2sp.org/httpsig-pq@v1.0.0#algorithms](https://c2sp.org/httpsig-pq@v1.0.0#algorithms) |

These identifiers permanently name the algorithms defined by this version. A future compatible version of this
specification may add identifiers but MUST NOT change the meaning of these identifiers.

## Security considerations

Applications inherit the security considerations of RFC 9421, including signature replay, insufficient component
coverage, algorithm confusion and downgrade attacks, multiple-signature confusion, and the requirement to match covered
components to the target message.

The 32-octet seed `ξ` is the complete private-key representation `Ks` defined by this document. Possession of `Ks`
permits regeneration of every private value used by ML-DSA. It MUST remain secret, MUST be generated with the randomness
quality required by FIPS 204 Section 3.6.1, and SHOULD be destroyed when no longer needed along with the corresponding
derived `sk` and any other cached private-key material.

FIPS 204 permits deterministic signing, but recommends hedged signing because fresh signing randomness helps mitigate
side-channel and fault attacks. Implementations that use deterministic signing need protections appropriate to their
execution environment. Deterministic signing is used in the test vectors for reproducibility and is not a production
recommendation.

ML-DSA signatures are substantially larger than pre-quantum signatures. Before field names, labels, and delimiters,
their RFC 4648 Base64 encodings are 3228, 4412, and 6172 octets for ML-DSA-44, ML-DSA-65, and ML-DSA-87 respectively.
HTTP implementations and intermediaries need field-size limits that accommodate the selected parameter set, while still
applying resource limits appropriate to untrusted inputs.

Applications SHOULD enable only the parameter sets they use and MUST bind each key to its intended algorithm. An
attacker-controlled `alg` parameter alone is not sufficient authorization to select an algorithm or key.

This document does not specify hybrid or composite signature schemes. Applications can use RFC 9421's support for
multiple signatures on the same HTTP message, for example an Ed25519 signature and an ML-DSA signature with different
labels. Application profiles that require multiple signatures MUST specify which labels and algorithms are required and
MUST NOT treat one valid signature as satisfying a policy that requires more than one.
