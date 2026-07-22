# Passkey records

[c2sp.org/passkey-record](https://c2sp.org/passkey-record)

This document specifies an encoding for a WebAuthn credential record, or
*passkey record*, for use by Relying Parties (server applications and WebAuthn
server libraries) as an interoperable storage format, and as an opaque input to
verification.

It reuses the grammar of Password Hashing Competition (PHC) Strings and the
binary encoding of the WebAuthn authenticator data.

```
$webauthn$v=1$transports=hybrid+internal$<base64 authenticator data>
```

## Introduction

The WebAuthn specification defines an abstract credential record, but no
concrete representation. The encoding specified in this document is intended to
be an interoperable format for credential record storage, analogously to
password hash strings.

Like a password hash, a passkey record is immutable. (Mutable values include
essentially only the sign count and the backup state. The former is mostly
unused in large deployments. The latter can be extracted from the authentication
response upon log in.)

The record is sufficient for verification. The set of records associated with an
account can be the input of a login function, along with the request challenge
and the authenticator response.

## Format

In the PHC String syntax, a WebAuthn credential record has

- Function symbolic name: `webauthn`
- Version: `1`
- An optional `transports` parameter with value a `+`-separated list
- Salt: authenticator data

(According to [c2sp.org/phc-strings](https://c2sp.org/phc-strings), if there is
only one of salt and payload, it is considered a salt.)

### Prefix

A record MUST start with

```
$webauthn$v=1$
```

### Transports parameters

If available, the credential’s transports list MAY be encoded by joining each
transport name with a `+` character, and then appended to the prefix the string
`transports=`, followed by the encoded list and a `$` character. The list MUST
be sorted lexicographically and deduplicated.

If any of the transports contains characters besides lowercase letters,
uppercase letters, digits, `/`, `.` and `-`, the parameter MUST be omitted. If
the list is empty, the parameter MUST be omitted.

The transports are returned by the [`getTransports()` method of the
`AuthenticatorAttestationResponse` interface](https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse/getTransports),
and are encoded as the `.response.transports` array in the [JSON encoding](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/toJSON)
of an [`AuthenticatorAttestationResponse`](https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse)
returned by [`navigator.credentials.create()`](https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create).

Parsers MUST ignore other parameters.

### Payload

Next, the authenticator data is appended encoded with standard Base64 without
padding `=` signs or whitespace. The authenticator data MUST have the AT flag
set, indicating it was produced during registration.

The authenticator data is a binary structure [defined in the WebAuthn Level 3
specification](https://www.w3.org/TR/webauthn-3/#authenticator-data), is
returned by the [`getAuthenticatorData()` method of the `AuthenticatorAttestationResponse`](https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse/getAuthenticatorData),
and is the `.response.authenticatorData` value in the [JSON encoding](https://developer.mozilla.org/en-US/docs/Web/API/PublicKeyCredential/toJSON)
of an [`AuthenticatorAttestationResponse`](https://developer.mozilla.org/en-US/docs/Web/API/AuthenticatorAttestationResponse)
returned by [`navigator.credentials.create()`](https://developer.mozilla.org/en-US/docs/Web/API/CredentialsContainer/create).
Note that the JSON value is encoded with the *base64url* alphabet, while the
record must be encoded with the standard *base64* alphabet.

The authenticator data includes the Credential ID, the public key, the UV, BE,
and BS flags (*as of registration*), the AAGUID, and the hash of the Relying
Party ID.

## Recommended storage model

Records SHOULD be stored keyed by user ID only, and SHOULD NOT be indexed by
Credential ID. If there is no Credential ID index, Credential ID uniqueness
SHOULD NOT be enforced.

(Uniqueness is only necessary to avoid cross-account ambiguity, which is not an
issue if records are exclusively looked up by user ID.)

User IDs SHOULD be random identifiers with at least 120 bits of entropy.

Multiple records SHOULD be allowed per user ID.

WebAuthn doesn’t require storing anything else than user ID and passkey
record(s). Applications MAY store additional fields for the passkey management
UI, such as a nickname, and creation and last use timestamps.

## Test vectors [TODO]

- One canonical record per key type: P-256, RSA-2048, ML-DSA-44 (w3c/webauthn#2393).
- One with no transports (parameter omitted).
- One with several transports exercising sort/dedup and a
  well-formed-but-unregistered value.
- One with extra parameters, with and without transports
- One with extension data present (ED flag set).
- Negative vectors, each with the reason it must be rejected: padded
  B64, base64url, non-canonical trailing bits, missing `v=1`, empty `transports=`, unsorted transports, duplicate transports, AT flag clear, trailing
  bytes after the COSE key, non-canonical CBOR in the COSE key, invalid public keys
- For each positive vector, give the decoded fields (credential ID, SPKI,
  AAGUID, flags, algorithm) so implementations can check accessors and
  not just round-tripping, and the AttestationResponse JSON so implementations can check encoding. (Where possible, generate them from a Chrome soft token.)
