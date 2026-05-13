# Transparency Log Witness Protocol

This document describes a synchronous HTTP-based protocol to obtain
[cosignatures][] from transparency log witnesses.

[cosignatures]: https://c2sp.org/tlog-cosignature
[bastion]: https://c2sp.org/https-bastion
[checkpoint]: https://c2sp.org/tlog-checkpoint@v1.0.0
[note]: https://c2sp.org/signed-note@v1.0.0
[subtree]: https://datatracker.ietf.org/doc/html/draft-ietf-plants-merkle-tree-certs-03#section-4
[draft-ietf-plants-merkle-tree-certs-03]: https://datatracker.ietf.org/doc/html/draft-ietf-plants-merkle-tree-certs-03

## Conventions used in this document

The base64 encoding used throughout is the standard Base 64 encoding specified
in [RFC 4648][], Section 4.

`U+` followed by four hexadecimal characters denotes a Unicode codepoint, to be
encoded in UTF-8. `0x` followed by two hexadecimal characters denotes a byte
value in the 0-255 range.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][] [RFC 2119][] [RFC
8174][] when, and only when, they appear in all capitals, as shown here.

[RFC 4648]: https://www.rfc-editor.org/rfc/rfc4648.html
[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html
[RFC 6962]: https://www.rfc-editor.org/rfc/rfc6962.html

## Introduction

This protocol allows clients, usually logs, to obtain cosignatures from
witnesses, making it possible to produce self-contained inclusion proofs that
can be verified offline. When producing a new checkpoint, the log reaches out to
witnesses to request cosignatures over it, providing a consistency proof.
Witnesses verify that the checkpoint is consistent with their previously
recorded state of the log (if any), and return a timestamped cosignature.

A witness is an entity exposing an HTTP service identified by a name and a
public key. Each witness is configured with a list of supported log public keys.
For each log, uniquely identified by its origin line, the witness is only
required to keep track of the latest checkpoint it observed and verified.

Only logs and sometimes monitors (see the end of this specification) are
expected to communicate directly with the witnesses.  There is no authentication
of requests beyond the validation of the signature on the checkpoint.

Witnesses are designed to scale well with a large number of rarely active logs,
and to support diverse log designs, including low-latency and "serverless" logs,
in order to enable the creation of a public network of interoperable witnesses.

Some witnesses might also expose an optional, additional API to produce cosigned
[subtrees][subtree] from subsets of previously observed checkpoints. These signed
subtrees can be used to provide more efficient proofs of inclusion in some
ecosystems.

## HTTP Interface

A witness is defined by a name, a public key, and by two URL prefixes: the
*submission prefix* for write APIs and the *monitoring prefix* for read APIs.

A witness MAY use the same value for both the *submission prefix* and the
*monitoring prefix*.

If exposing the machine holding the witness key material directly to the
Internet is undesirable, operators MAY use a [bastion][].

Clients SHOULD use, and witnesses SHOULD support, HTTP keep-alive HTTP
connections to reduce latency and load due to connection establishment.

### add-checkpoint

The `add-checkpoint` call is used to submit a new checkpoint to the witness,
along with a consistency proof from a previous checkpoint, and returns the
cosignature.

    POST <submission prefix>/add-checkpoint

The request MUST be an HTTP POST.

The request body MUST be a sequence of
  - an old size line,
  - zero or more consistency proof lines,
  - and an empty line,
  - followed by a [checkpoint][].

Each line MUST terminate in a newline character (U+000A).

The old size line MUST consist of the string `old`, a single space (0x20),
and the tree size of the previous checkpoint encoded as an ASCII decimal with no
leading zeroes (unless the size is zero, in which case the encoding MUST be `0`).

Each consistency proof line MUST encode a single hash in base64. The client MUST
NOT send more than 63 consistency proof lines.

The submitted checkpoint MAY include multiple signatures.

Example request body:

    old 20852014
    PlRNCrwHpqhGrupue0L7gxbjbMiKA9temvuZZDDpkaw=
    jrJZDmY8Y7SyJE0MWLpLozkIVMSMZcD5kvuKxPC3swk=
    5+pKlUdi2LeF/BcMHBn+Ku6yhPGNCswZZD1X/6QgPd8=
    /6WVhPs2CwSsb5rYBH5cjHV/wSmA79abXAwhXw3Kj/0=

    example.com/behind-the-sofa
    20852163
    CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=

    — example.com/behind-the-sofa Az3grlgtzPICa5OS8npVmf1Myq/5IZniMp+ZJurmRDeOoRDe4URYN7u5/Zhcyv2q1gGzGku9nTo+zyWE+xeMcTOAYQ8=
    — example.com/behind-the-sofa opLqBQsREYCgu6xQkYQwJr9fo45a62DN9EdmHXnZdXNqlcVGlCum2Wks+49/V6267UEjw6QUXTS5Rovnzv++qbSzm9Q=

The witness MUST verify the checkpoint signature against the public key(s) it
trusts for the checkpoint origin, and it MUST ignore signatures from unknown
keys. If the checkpoint origin is unknown, the witness MUST respond with a "404
Not Found" HTTP status code. The witness MUST respond with a "403 Forbidden"
HTTP status code if either no signature from a trusted key for the origin is
present, or a signature line's key name and ID match a trusted key but the
signature itself fails to verify (such a note is malformed per
[signed-note][]).

The old size MUST be equal to or lower than the checkpoint size. Otherwise,
the witness MUST respond with a "400 Bad Request" HTTP status code.

The witness MUST check that the old size matches the size of the latest
checkpoint it cosigned for the checkpoint's origin (or zero if it never cosigned
a checkpoint for that origin). If it doesn't match, the witness MUST respond
with a "409 Conflict" HTTP status code. The response body MUST consist of the
tree size of the latest cosigned checkpoint in decimal, followed by a newline
(U+000A). The response MUST have a `Content-Type` of `text/x.tlog.size`.

If a client doesn't have information on the latest cosigned checkpoint, it MAY
initially make a request with a old size of zero to obtain it.

The consistency proof lines MUST encode a Merkle Consistency Proof from the old
size to the checkpoint size according to [RFC 6962][], Section 2.1.2. The proof
MUST be empty if the old size is zero. If the Merkle Consistency Proof doesn't
verify, the witness MUST respond with a "422 Unprocessable Entity" HTTP status
code.

If the old size matches the checkpoint size, the witness MUST check that the
root hashes are also identical. If they don't match, the witness MUST respond
with a "409 Conflict" HTTP status code.

If the origin is known, and the signature is valid, the witness MAY log the
request even if the consistency proof doesn't verify (but MUST NOT cosign the
checkpoint) as it might be proof of log misbehavior.

If all the checks above pass, the witness MUST update its record of the latest
cosigned checkpoint and respond with a "200 Success" HTTP status code. The
response body MUST be a sequence of one or more [note][] signature lines, each
starting with the `—` character (U+2014) and ending with a newline character
(U+000A). The signatures MUST be [cosignatures][] from the witness key(s) on the
checkpoint. Witnesses SHOULD use ML-DSA-44 [cosignatures][]. If the cosignature
format supports subtrees, the cosignature returned by the witness MUST be for
the entire tree in the submitted checkpoint, i.e. start MUST be zero and end
MUST be the checkpoint size. The cosignature MUST NOT omit the timestamp, i.e.
the timestamp MUST NOT be zero.

Example response body:

    — witness.example/w1 CMp+6LWBU0anHGH5aNDTJkH/gj79sG+T6+iP2ThYN5krrDJbR1HDnucjL39QsZTSvVjyQLrdk3DXDqI5G2HgLatVs0pWh6Up69HVOw==
    — witness.example/w1 I7rEps0pvK2UqkS2gSpVUDhrhVtQV9lgF6pRrWAvjJHjyWpW7VcE3SiOlVlbQNt64vWhO+DlkL0+UfzuOBMh9ChdMkP1vi/lCAsmlw==
    — witness.example/w2 AWui8Sk55XjYLOijihBjhqEH6nS1ndDymE0a+6idX7pLcnoB+dhnz0854aLZgrrKbYKA7nC3HNJhm/kWl7oJlqU3rXXvpysAdyP3wQ==

The client MUST ignore any cosignatures from unknown keys. To parse the
response, the client MAY concatenate it to the checkpoint, and use a [note][]
verification function configured with the witness keys it trusts. If that call
succeeds, it can move the valid signatures to its own view of the checkpoint.

The witness MUST persist the new checkpoint before responding. Note that
checking the old size against the latest checkpoint and persisting the new
checkpoint must be performed atomically, otherwise the following race can occur:

1. Request A with size N is checked for consistency.
2. Request B with size N+K is checked for consistency.
3. The stored size is updated to N+K for request B.
4. A cosignature for N+K is returned to request B.
5. The stored size is updated to N for request A, *rolling back K leaves*.
6. A cosignature for N is returned to request A.

### sign-subtree

The `sign-subtree` call is used to request a [subtree][] cosignature from the
witness, by providing a checkpoint and a subtree consistency proof.

It is OPTIONAL for a witness to support this API.

    POST <submission prefix>/sign-subtree

The request MUST be an HTTP POST.

The request body MUST be a sequence of
  - a subtree range line,
  - a subtree hash line,
  - zero or more subtree cosignature lines,
  - zero or more consistency proof lines,
  - and an empty line,
  - followed by a reference [checkpoint][].

Each line MUST terminate in a newline character (U+000A).

The subtree range line MUST consist of the string `subtree`, a single space
(0x20), the subtree start encoded as an ASCII decimal with no leading zeroes
(unless start is zero, in which case the encoding MUST be `0`), a single space
(0x20), and the subtree end encoded as an ASCII decimal with no leading zeroes.

The subtree hash line MUST be the Merkle Tree hash of the subtree encoded in
base64.

Each subtree cosignature line MUST be a [note][] signature line, starting with
the `—` character (U+2014). The subtree cosignature lines are a DoS protection
mechanism, as described below, and MAY be omitted. If present, they MUST encode
a valid cosignature on the subtree. If the cosignature format supports
timestamps, the timestamp MUST be zero. Witnesses MUST ignore subtree
cosignatures from unknown keys. The client MUST NOT send more than 8 subtree
cosignature lines.

Each consistency proof line MUST encode a single hash in base64. The client MUST
NOT send more than 63 consistency proof lines.

The client MUST NOT send more than 8 checkpoint signatures. The client MAY omit
the signatures entirely, if the witness is expected to statefully verify the
checkpoint. If signatures are omitted, the body MUST terminate with the newline
character that concludes the checkpoint body, without empty lines.

Example request body:

```
subtree 8 13
mbsQCg+dEIMGlpqeGgk94JutQwKKS2Lo5IuDhKmDjiU=
— example.com/behind-the-sofa nTSsCq08mZc1UhXhqNcId9B3gLbf0L[...]aLETmnVSNm/Ow==
CD82D2LDm0phY0+xKbHyZfq3Hw21lVkuV7Zis5EFg0k=
h/ghL5nyaXTIBAklqDnisM+SFdbA3izoGZ5oRYMZzc0=
8qtnAAU9sTKQx/zt3E4v8Jt2a9IMQUf0QUawvePF9y0=
KuO5BNOmginG34Lm5G3e2GuiWliGo3K0ebzGpvI0fEg=

example.com/behind-the-sofa
14
/CcKVZM9n65aH7jLaIZuUB4/MSlEFQ4+ldwUC21rDHM=

— witness.example/w1 LijDAFSpKvDUj+ZtaJ4lUVcnvnooXd[...]azezGX6o5Vulg==
```

The same request without the subtree cosignatures and checkpoint signatures:

```
subtree 8 13
mbsQCg+dEIMGlpqeGgk94JutQwKKS2Lo5IuDhKmDjiU=
CD82D2LDm0phY0+xKbHyZfq3Hw21lVkuV7Zis5EFg0k=
h/ghL5nyaXTIBAklqDnisM+SFdbA3izoGZ5oRYMZzc0=
8qtnAAU9sTKQx/zt3E4v8Jt2a9IMQUf0QUawvePF9y0=
KuO5BNOmginG34Lm5G3e2GuiWliGo3K0ebzGpvI0fEg=

example.com/behind-the-sofa
14
/CcKVZM9n65aH7jLaIZuUB4/MSlEFQ4+ldwUC21rDHM=
```

start MUST be less than end, and end MUST be less than or equal to the
checkpoint size. Otherwise, the witness MUST respond with a "400 Bad Request"
HTTP status code.

The consistency proof lines MUST encode a Subtree Consistency Proof from the
subtree to the checkpoint according to
[draft-ietf-plants-merkle-tree-certs-03][], Section 4.4. If the Merkle
Consistency Proof doesn't verify, the witness MUST respond with a "422
Unprocessable Entity" HTTP status code.

The witness MUST verify that the checkpoint is consistent with its view of the
log identified by the origin line. It MAY do so in multiple ways:

 - Statelessly, by checking a cosignature from its own key on the submitted
   checkpoint.

 - With access to one or more recently signed checkpoints, by comparing the
   submitted checkpoint against those. If the checkpoint is not known, the
   witness MAY respond with a "409 Conflict" HTTP status code, and the response
   body MUST consist of a known checkpoint for the same origin. In this case,
   the witness SHOULD remember and accept the last few signed checkpoints, to
   minimize conflicts.

 - With access to the full tree state, by checking that the checkpoint size is
   less than or equal to the size of the latest checkpoint it cosigned for the
   checkpoint's origin, and that a consistency proof can be constructed from the
   latest checkpoint to the submitted checkpoint.

Note that the stateful verification mechanisms above only require read access to
the witness state and can operate on stale state safely.

If all the checks above pass, the witness MUST respond with a "200 Success" HTTP
status code. The response body MUST be a sequence of one or more [note][]
signature lines for the subtree, each starting with the `—` character (U+2014)
and ending with a newline character (U+000A). The signatures SHOULD be ML-DSA-44
[cosignatures][], and SHOULD be from one or more of the same witness key(s) that
signed the checkpoint. If the cosignature format supports timestamps, the
timestamp MUST be zero.

Example response body:

    — witness.example/w1 GuvvwNqqDmhh5OoDEJyEWiNUB2F1vR[...]qRHf6aZYGsZKA==

Unlike checkpoints, which can only progress at the pace of the log, the set of
potential subtree inputs is very large. This API is therefore more vulnerable to
DoS attacks, although note that the resource cost of signing a subtree is
equivalent to the cost of establishing a TLS connection. To mitigate that,
witnesses MAY apply one or more of the following mechanisms:

 - regular rate-limit or authentication of clients, which is out-of-scope for
   this document;

 - only cosigning recent subtrees and/or caching signed subtrees;

 - requiring clients to provide a valid subtree cosignature from a key that is
   known to only cosign a limited set of subtrees.

### TBD Monitor Retrieval Mechanism

TODO: For a transparency system to be effective, it must not be possible to
partition clients from monitors, either by splitting the tree or by serving a
stale view to monitors. That [may require monitors to obtain more cosignatures
than clients][byzantine-witnesses]. Some logs can facilitate that by fetching a
larger set of cosignatures (e.g. in the background) and serving those to
monitors. Some logs might not be capable of doing that, and might need witnesses
to coordinate directly with monitors. Such a mechanism is still under
discussion, and will have to be designed with an eye towards witness
sustainability.

[byzantine-witnesses]: https://git.glasklar.is/sigsum/project/documentation/-/blob/main/archive/2023-11-byzantine-witnesses.pdf
