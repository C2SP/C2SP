# OIDs

C2SP has been assigned a Private Enterprise Number ([RFC 9371]). This PEN is the
root of OIDs used as identifiers in C2SP specifications.

C2SP OIDs are assigned by the [C2SP stewards].

[RFC 9371]: https://www.rfc-editor.org/rfc/rfc9371.html
[C2SP stewards]: MAINTAINERS.md#stewards

## Requesting a C2SP OID assignment

To request an OID for an entity, [create an issue] giving details about the
nature or purpose of the entity, and referencing the specification that the
entity is (or will be) defined in or related to.

The stewards decide whether to grant the assignment, and what structure the OID
will have.

[create an issue]: https://github.com/C2SP/C2SP/issues/new?template=oid.md

## Registry of assigned C2SP OIDs

| OID | Entity |
| --- | --- |
| `1.3.6.1.4.1.64829` | [C2SP] |
| `1.3.6.1.4.1.64829.1` | [age] |
| `1.3.6.1.4.1.64829.1.1` | X.509v3 critical extension, containing a 64-byte ML-KEM-768 seed encoded as a DER Octet String. Used by `age-plugin-yubikey` for storing the PQ half of the [hybrid tagged native age recipient type] in YubiKeys with firmware versions that pre-date support for PQ algorithms. |

[C2SP]: https://c2sp.org
[age]: https://c2sp.org/age
[hybrid tagged native age recipient type]: https://c2sp.org/age#the-tagged-recipient-types
