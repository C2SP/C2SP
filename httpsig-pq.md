# Post-Quantum Algorithms for HTTP Message Signatures

[c2sp.org/httpsig-pq](https://c2sp.org/httpsig-pq)


- **Version**: v0.1.0
- **Authors**:
  - [Soatok Dreamseeker](https://github.com/soatok)

## Introduction

This document specifies HTTP Message Signature algorithm identifiers for post-quantum signature schemes.
As of v0.1.0, this only covers the ML-DSA signature algorithms standardized in
[FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).

HTTP Message Signatures are specified by [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html).
This document only defines new signature algorithms for that framework.
Signature base construction, the `Signature-Input` field, the `Signature` field, and message verification are otherwise
unchanged.

## Conventions used in this document

The base64 encoding used throughout is the standard Base 64 encoding specified in
[RFC 4648, Section 4](https://www.rfc-editor.org/rfc/rfc4648.html#section-4).

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED",
"NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in
[BCP 14](https://www.rfc-editor.org/info/bcp14) [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.html)
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174.html) when, and only when, they appear in all capitals, as shown here.

## Algorithms

The following values are defined for use in the RFC 9421 `alg` signature parameter.

| `alg` value  | FIPS 204 algorithm | Public key size | Signature size |
|--------------|--------------------|----------------:|---------------:|
| `ml-dsa-44`  | ML-DSA-44          |      1312 bytes |     2420 bytes |
| `ml-dsa-65`  | ML-DSA-65          |      1952 bytes |     3309 bytes |
| `ml-dsa-87`  | ML-DSA-87          |      2592 bytes |     4627 bytes |

For each algorithm, the public key is the raw FIPS 204 public key encoding for that parameter set.

The message to sign is the RFC 9421 signature base, exactly as bytes. Signers **MUST** use the FIPS 204 ML-DSA signing
operation for the selected parameter set with an empty context string. Verifiers **MUST** use the corresponding FIPS 204
ML-DSA verification operation with an empty context string.

The `Signature` field value is the raw FIPS 204 signature encoded as an RFC 9421 byte sequence. No prehashing,
external-mu processing, or additional framing is defined by this document.

When the `alg` parameter is present, verifiers MUST reject signatures where the algorithm does not match the configured
verification key's ML-DSA parameter set.

### Signing and Verification

For the selected `alg` value, `HTTP_SIGN(M, Ks)` takes the RFC 9421 signature base bytes `M` and a raw FIPS 204 ML-DSA
private key `Ks` for the corresponding parameter set, and returns the raw FIPS 204 signature `S`.

`HTTP_SIGN` **MUST** call the FIPS 204 signing operation for the selected parameter set directly on `M`, with the
context string set to the empty string. `HTTP_SIGN` **MUST NOT** prehash `M`, use external-mu processing, or add any
framing around `M`.

For the selected `alg` value, `HTTP_VERIFY(M, Kv, S)` takes the regenerated RFC 9421 signature base bytes `M`, a raw
FIPS 204 ML-DSA public key `Kv` for the corresponding parameter set, and a raw FIPS 204 signature `S`, and returns
`true` if the signature is valid and `false` otherwise.

`HTTP_VERIFY` **MUST** call the FIPS 204 verification operation for the selected parameter set directly on `M` and `S`,
with the context string set to the empty string. `HTTP_VERIFY` **MUST NOT** prehash `M`, use external-mu processing, or
add any framing around `M`.

Implementations **MUST** reject malformed public keys, malformed signatures, values with lengths that do not match the
selected parameter set, non-empty ML-DSA contexts, prehashed inputs, and any signature where the `alg` value does not
match the configured key's ML-DSA parameter set.

## Test vectors

The seed deterministically generates the key pair. ML-DSA signing is randomized, so the signatures below are sample
valid signatures and are not reproduced from the seed alone.

### ML-DSA-44

Algorithm: `ml-dsa-44`

Seed:

    c80d699b2daa47d54b8697f5a917c696400d7063b30a234d18ad672250ae42d9

Signature base:

```text
"@method": GET
"@target-uri": https://example.com/foo?param=Value&Pet=dog
"host": example.com
"date": Mon, 06 Jul 2026 20:00:00 GMT
"@signature-params": ("@method" "@target-uri" "host" "date");created=1783368000;keyid="test-key-mldsa44";alg="ml-dsa-44"
```

Public key:

```text
guWbbXQe/Y1a83/qIeU8MjIrRseICPuOyWzoGXk27Fia2lpk2uPxbEfh/iEmvY1z/LTtxSBFZS8zbgV04qa038ZokwE+QoBcISX0H4F9hEY3Oxg8SRtzrek0E+mBOc6R4ilBje5vodImgSMTMSXKuDz2PWqvrLY20AfLmMkLXZqVERYcW+S7iKyTP53cvtenYwealt3MGcZxLKRAMnCGBY3pRfj1xn6czY6OuMYNuJaW1rAeL2BeVpNA+XBA+HUHS1yTYOGw93ddFe9lw0RDex7Pw+tht/n31gggrR4D0kmE8L88Q5c2qWuQtxk9+cmHTm3u1WuG/vCRiubTA3DmY0pK1fO1etarscNRnZ06q5UfTgSQOMqR/PLXtqT9cZiN8GWQvum15uVuxXCubB4r7T3nz2ijyBPQfo+Ywd10QxI8dpGpsBd9SEslLo+esyFDt7+9t4c702PNC0121oI18PriNlKxjxshQljNnrXSZ4eCvhHrY5Le8B/mTwsb/LYPbBvktCecvkRxboTjhyq2anblDt5Hp55gn+0YRWUz7myuDjBD/+a2riHzOXCoLOtGvsfVTLAwLPYj/AIBbdVFrGq9MKldtcgiqTWhG6JWD/dxFrfUT4YIf2yWO9AbhkgkgPynKmV82sLda4L3JaABwSXVAB1vzDmxfQ17orBFxX2pK23G5EmrG8Ix/1O9NJ35LSxkZhUmNs+4zm9GRaChPbw04q//Gc9CPiE3xvv/BrRms5mIiRl7zT8o2mgNs/APM45mJrKClmYRQllKVwnKBj+njZkDv1CG2WeBv01COmic4P4EEraSmKO8I5sJ98gpTiA9jeBuvloLYdAInPyZui01GyQO4P3OETyAVqggBGIvajxWuio7eL+4XZmkX3AMb5XrfWtlfYCKUzhodcv7NM6M4LizEh0KZ8qSHsnVZxqwb5J9hb4oiR5/N7sgxjjtiBsbg/vJ1UmBZZR6hPjnLbLDTZ6PUMjeQNdoYGL0Cv4ESloaEtc4vhW/Aa2roIyoAM/kimrHYztNknxZK3nLQ9PXVp9Np1okp4VPUkOfHvy6Bk2WPQd8vdwrfE3xOPGrkhzdmlcsVEp3rIAW4s4Hem2A99CFSkbPePEEPG4uB3sVl73X+sr8+X7jFkiiy686eV73zQTrqL4OnrYJIkaZr6zLXHccvm1txmftmtS3WH3Ny0hGVjwxnu1femv2++2pZpZr67//WBksxPOG4xk6AA7xrHEAjRFA0b0g6AC3+WuZmaNCNMd8YdibEt/WHKg7uGWYetMf45cWxPxZmNl+jddlf1btTAfYZ+eXla3Tx/pg5fU2EWTXyTOVIRdRwAOpZHG7jFYCxRE2SWFFM2lwjLxzso69uABhM1zraUxo6TfOalw1x7S1NkTowesaJPlTMmr43N5hdbRyDD6qmcCSNNjDICvK/fv3ijSY0lueglt1Jf7O1fi9/s0CNGf8E/pQohdb/pzGhSlJRo73hC/wTmLEjFukAYNdNeJO8Fxge7j6rLHIOu22q8lK0DSsWqXXeFYt5mKmdTOFHN6soJQ7Uk43HgwoMreCn6xJQhl87CZu4SUzr5XztrsOV/YF5u5IYY8cDneoZW+0ldE+/8bvI8gi352YmfL9ZY5TacDexbl0S+hGbR7IPHh6av0N+odj2uBNt4Cjb3Mt3aYwQi2Yh9vD+CaGcz5AO67GAf7pIpS8naBrzQeNjdOYLxu6VcXT4zLO9Gu1Uv+RvkLPaalcAQ==
```

Signature:

```text
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
```

### ML-DSA-65

Algorithm: `ml-dsa-65`

Seed:

    40342eccce31032955f04c14256fa8cb6b6269bdc22d6ee62fd00d9338759773

Signature base:

```text
"@method": GET
"@target-uri": https://example.com/foo?param=Value&Pet=dog
"host": example.com
"date": Mon, 06 Jul 2026 20:00:00 GMT
"@signature-params": ("@method" "@target-uri" "host" "date");created=1783368000;keyid="test-key-mldsa65";alg="ml-dsa-65"
```

Public key:

```text
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
```

Signature:

```text
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
```

### ML-DSA-87

Algorithm: `ml-dsa-87`

Seed:

    0cd2f7cc3f9772ad23031ef37aea63b3825fb46bdb5d5cc4fb620ecccc5e630b

Signature base:

```text
"@method": GET
"@target-uri": https://example.com/foo?param=Value&Pet=dog
"host": example.com
"date": Mon, 06 Jul 2026 20:00:00 GMT
"@signature-params": ("@method" "@target-uri" "host" "date");created=1783368000;keyid="test-key-mldsa87";alg="ml-dsa-87"
```

Public key:

```text
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
```

Signature:

```text
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
```

### Negative test cases

For each vector above, verifiers **MUST** reject the following variants. Accepting any of them indicates a bug in
signature-base construction, algorithm binding, or strict ML-DSA input validation.

| Test                      | Change                                                                                                                            | Expected result |
|---------------------------|-----------------------------------------------------------------------------------------------------------------------------------|-----------------|
| Modified component        | Change the `date` line from `Mon, 06 Jul 2026 20:00:00 GMT` to `Mon, 06 Jul 2026 20:00:01 GMT` while keeping the same signature.  | Reject          |
| Missing covered component | Remove the `"@target-uri"` line from the signature base while keeping the same signature.                                         | Reject          |
| Algorithm substitution    | Replace the `alg` value in `@signature-params` with either of the other two identifiers while keeping the same key and signature. | Reject          |
| Wrong key                 | Verify the signature with the public key from any other vector.                                                                   | Reject          |
| Signature bit flip        | Flip the low bit of the first signature byte.                                                                                     | Reject          |
| Truncated signature       | Remove the final signature byte.                                                                                                  | Reject          |
| Extended signature        | Append one `0x00` byte to the signature.                                                                                          | Reject          |
| Non-empty ML-DSA context  | Verify with any non-empty FIPS 204 context string.                                                                                | Reject          |
| Prehashed message         | Verify against `SHA-256(signature base)` instead of the signature base itself.                                                    | Reject          |

## IANA Considerations

This document requests registration of the following values in the HTTP Signature Algorithms registry.

| Algorithm Name | Description               | Status | Reference                     |
|----------------|---------------------------|--------|-------------------------------|
| `ml-dsa-44`    | ML-DSA-44 using FIPS 204  | Active | `c2sp.org/httpsig-pq@v0.1.0`  |
| `ml-dsa-65`    | ML-DSA-65 using FIPS 204  | Active | `c2sp.org/httpsig-pq@v0.1.0`  |
| `ml-dsa-87`    | ML-DSA-87 using FIPS 204  | Active | `c2sp.org/httpsig-pq@v0.1.0`  |

## Security Considerations

Applications using these algorithms inherit the security considerations of RFC 9421, including signature replay,
insufficient component coverage, and matching covered components to the target message.

ML-DSA signatures are substantially larger than pre-quantum signatures. HTTP implementations and intermediaries need to
accept header field values large enough for the selected parameter set.

An application SHOULD support only the ML-DSA parameter set or sets it actually uses.

This document does not specify hybrid (a.k.a. composite) signature schemes. Applications that desire this functionality
can use RFC 9421's support for multiple signatures on the same HTTP message. For example, `sig1` can use `ed25519`
while `sig2` uses `ml-dsa-44`. The signature bases will differ because each signature has its own `@signature-params`,
but the underlying HTTP message can be the same. In such a setup, application profiles SHOULD specify which signature
labels are required, and verifiers **MUST NOT** treat the presence of any one valid signature as satisfying such a
policy unless that signature is sufficient under the application's policy.
