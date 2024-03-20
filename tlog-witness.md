# The Witness Protocol

This document describes a synchronous HTTPS-based protocol to obtain
[cosignatures][] from transparency log witnesses.

[cosignatures]: https://c2sp.org/tlog-cosignature
[bastion]: https://c2sp.org/https-bastion
[checkpoint]: https://c2sp.org/tlog-checkpoint
[note]: https://c2sp.org/signed-note

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
Witnesses verify that the checkpoint is consistent with the previous state of
the tree, and return a timestamped cosignature.

A witness is an entity exposing an HTTPS service identified by a name and a
public key. Each witness is configured with a list of supported log public keys.
For each log, uniquely identified by its origin line, the witness keeps only
track of the latest checkpoint it observed and verified.

Clients are not expected to communicate directly with the witnesses, logs and
(sometimes) monitors are, but there is no authentication of requests beyond the
validation of the signature on the checkpoint.

Witnesses need to be operated by trusted, reliable entities with minimal churn.
Log deployments pick a witness trust policy that gets deployed into clients and
might be difficult or impossible to change. Developing a healthy ecosystem of
witnesses might be the biggest hurdle to widespread tlog success. It’s
impractical to build a separate witness ecosystem for each application, so it’s
important that witnesses be public, interoperable, and scalable. As for
quantity, there should be more than a few, but once reached a critical mass each
additional witness has diminishing marginal value. Additional log deployments,
on the other hand, don’t have diminishing returns and are a desirable goal.
Because of this, witnesses are designed to scale well with a large number of
rarely active logs, and to support diverse log designs, including low-latency
and "serverless" logs.

## HTTPS Interface

A witness is defined by a name, a public key, and by two URL prefixes: the
*submission prefix* for write APIs and the *monitoring prefix* for read APIs.

A witness MAY use the same value for both the *submission prefix* and the
*monitoring prefix*.

If exposing the machine holding the witness key material directly to the
Internet is undesirable, operators MAY use a [bastion][].

### add-checkpoint

The `add-checkpoint` call is used to submit a new checkpoint to the witness,
along with a consistency proof from a previous checkpoint, and returns the
cosignature.

    POST <submission prefix>/add-checkpoint

The request MUST be an HTTP POST. Clients SHOULD use and witnesses SHOULD
support keep-alive HTTP connections to reduce latency and load due to connection
establishment.

The request body MUST be a sequence of
  - a previous size line,
  - zero or more consistency proof lines,
  - and an empty line,
  - followed by a [checkpoint][].

Each line MUST terminate in a newline character (U+000A).

The previous size line MUST consist of the string `old`, a single space (0x20),
and the tree size of the previous checkpoint encoded as an ASCII decimal with no
leading zeroes (unless the size is zero, in which case the encoding MUST be `0`).

Each consistency proof line MUST encode a single hash in base64. The client MUST
NOT send more than 63 consistency proof lines.

The submitted checkpoint MAY include multiple signatures. 

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
trusts for the checkpoint origin, and it MUST ignore signature from unknown
keys. If the checkpoint origin is unknown, the witness MUST respond with a "404
Not Found" HTTP status code. If none of the signatures verify against a trusted
public key, the witness MUST respond with a "403 Forbidden" HTTP status code.

The previous size MUST be equal to or lower than the checkpoint size. Otherwise,
the witness MUST respond with a "400 Bad Request" HTTP status code.

The witness MUST check that the previous size matches the size of the latest
checkpoint it cosigned for the checkpoint's origin (or zero if it never cosigned
a checkpoint for that origin). If it doesn't match, the witness MUST respond
with a "409 Conflict" HTTP status code. The response body MUST consist of the
tree size of the latest cosigned checkpoint in decimal, followed by a newline
(U+000A). The response MUST have a `Content-Type` of `text/x.tlog.size`.

If a client doesn't have information on the latest cosigned checkpoint, it MAY
initially make a request with a previous size of zero to obtain it.

The consistency proof lines MUST encode a Merkle Consistency Proof from the
previous size to the checkpoint size according to [RFC 6962][], Section 2.1.2. The
proof MUST be empty only if the previous size is zero or if it matches the size
in the checkpoint. If the Merkle Consistency Proof doesn't verify, the witness
MUST respond with a "422 Unprocessable Entity" HTTP status code.

If the origin is known, and the signature is valid, the witness SHOULD log the
request even if the consistency proof doesn't verify (but MUST NOT cosign the
checkpoint) as it might be proof of log misbehavior.

If all the checks above pass, the witness MUST update its record of the latest
cosigned checkpoint and respond with a "200 Success" HTTP status code. The
response body MUST be a sequence of one or more [note][] signature lines, each
starting with the `—` character (U+2014) and ending with a newline character
(U+000A). The signatures MUST be [cosignatures][] from the witness key(s) on the
checkpoint.

    — witness.example/w1 CMp+6LWBU0anHGH5aNDTJkH/gj79sG+T6+iP2ThYN5krrDJbR1HDnucjL39QsZTSvVjyQLrdk3DXDqI5G2HgLatVs0pWh6Up69HVOw==
    — witness.example/w1 I7rEps0pvK2UqkS2gSpVUDhrhVtQV9lgF6pRrWAvjJHjyWpW7VcE3SiOlVlbQNt64vWhO+DlkL0+UfzuOBMh9ChdMkP1vi/lCAsmlw==
    — witness.example/w2 AWui8Sk55XjYLOijihBjhqEH6nS1ndDymE0a+6idX7pLcnoB+dhnz0854aLZgrrKbYKA7nC3HNJhm/kWl7oJlqU3rXXvpysAdyP3wQ==

The client MUST ignore any cosignatures from unknown keys. To parse the
response, the client MAY concatenate it to the checkpoint, and use a [note][]
verification function configured with the witness keys it trusts. If that call
succeeds, it can move the valid signatures to its own view of the checkpoint.

The witness MUST persist the new checkpoint before responding. Note that
checking the previous size against the latest checkpoint and persisting the new
checkpoint must be performed atomically, otherwise the following race can occur:

1. Request A with size N is checked for consistency.
2. Request B with size N+K is checked for consistency.
3. The stored size is updated to N+K for request B.
4. A cosignature for N+K is returned to request B.
5. The stored size is updated to N for request A, *rolling back K leaves*.
6. A cosignature for N is returned to request A.

### roster

The `roster` returns the list of the latest checkpoints witnessed for each known
origin.

    GET <monitoring prefix>/roster

The request MUST be an HTTP GET.

Note that this endpoint MAY be served from a different prefix from that of the
`add-checkpoint` endpoint, to reflect the fact that this endpoint serves a
different set of clients with potentially different request patterns and rate
limits, and to facilitate delegating it to a static hosting service.

The response body MUST be a [note][] signed by the witness key(s). The signed
note body MUST be a sequence of a header line, a timestamp line, and three
checkpoint lines for each known log that submitted at least one checkpoint.

Each line MUST terminate in a newline character (U+000A).

The header line MUST be the fixed string `roster/v1`, for domain separation.

The timestamp line MUST consist of the string `time`, a single space (0x20), and
the time at which this roster was generated in seconds since the UNIX epoch
(January 1, 1970 00:00 UTC) encoded as an ASCII decimal with no leading zeroes.

The three checkpoint lines MUST be the first three lines of the latest witnessed
checkpoint for each known origin that submitted at least one checkpoint. The
origins MAY be listed in any order.

    roster/v1
    time 1679315147
    sigsum.org/v1/a275973457e5a8292cc00174c848a94f8f95ad0be41b5c1d96811d212ef880cd
    15368405
    31JQUq8EyQx5lpqtKRqryJzA+77WD2xmTyuB4uIlXeE=
    example.com/footree
    8923847
    9gPZU/wiV/idmMaBmkF8s+S6mNWW7zyBAT0Rordygf4=
    sigsum.org/v1/6a04bb2889667e322c5818fc10c57ab7e8095527b505095dbbdec478066df4a2
    99274999
    jIKavLHDS5/ygY56ZVObZYPz5CS+ejR0fl6VacWMvmw=

    — witness.example.com/w1 jWbPPwAAAABkGFDLEZMHwSRaJNiIDoe9DYn/zXcrtPHeolMI5OWXEhZCB9dlrDJsX3b2oyin1nPZ\nqhf5nNo0xUe+mbIUBkBIfZ+qnA==

Witnesses MUST commit publicly to the period at which they update the roster,
and ensure that any caching system won't interfere with the roster URL response
visibly updating at least every period.

This endpoint is provided for the benefit of monitors. By obtaining a recent
roster from a quorum of witnesses and comparing the tree in the roster with that
in the most recent checkpoint, a monitor can ensure the "freshness" of the
checkpoint it is inspecting, as well as ensure it was not partitioned on a split
view. Otherwise, a log could hide entries from a monitor by pretending it has
stopped issuing tree heads, or by showing different views to different subsets
of witnesses. <!-- TODO(filippo): elaborate on when, how, and why monitors need
to use rosters to defend against split view attacks. See https://git.glasklar.is/sigsum/project/documentation/-/blob/main/archive/2023-11-byzantine-witnesses.pdf -->
