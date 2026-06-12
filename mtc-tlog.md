# Merkle Tree Certificates With Tiled Transparency Logs

This document defines a profile of [Merkle Tree Certificates][] (MTCs) that uses
[tiled transparency logs][].

[Merkle Tree Certificates]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.html
[tiled transparency logs]: https://c2sp.org/tlog-tiles

## Conventions used in this document

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][] [RFC 2119][]
[RFC 8174][] when, and only when, they appear in all capitals, as shown here.

[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html

## Parameters

An MTC CA following this profile has, in addition to [CA parameters][] defined
in the MTC specification, a *CA prefix URL*. The CA prefix URL determines the
serving URL for each issuance URL, as described below.

When such a CA is [represented as an X.509 certificate][], the certificate has a
non-critical X.509 extension with OID 1.3.6.1.4.1.44363.47.3 and syntax an
IA5String, as defined below. The IA5String's contents are the CA prefix URL.
Presence of this extension indicates that the certificate subject follows this
specification.

``` asn.1
id-mtcTlogPrefixURL OBJECT IDENTIFIER ::= { 1 3 6 1 4 1 44363 47 3 }

ext-mtcTlogPrefixURL EXTENSION ::= {
    SYNTAX IA5String
    IDENTIFIED BY id-mtcTlogPrefixURL
    CRITICALITY FALSE
}
```

[CA parameters]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.html#name-certification-authorities
[represented as an X.509 certificate]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.html#name-representing-certification-

## Representing Trust Anchor IDs

MTC entities are named using [trust anchor IDs][]. This section defines how to
map these to tiled transparency log [checkpoint][] origins and [witness][]
names. A trust anchor ID is represented as the concatenation of:

* The 16-byte ASCII string `oid/1.3.6.1.4.1.`, including the trailing period
* The trust anchor ID's [ASCII representation][]

This is equivalent to the concatenation of:

* The four-byte ASCII string `oid/`
* The trust anchor ID as a full OID, in dotted decimal notation

For example, the trust anchor ID `32473.1` is represented as
`oid/1.3.6.1.4.1.32473.1`.

[ASCII representation]: https://www.ietf.org/archive/id/draft-ietf-tls-trust-anchor-ids-04.html#name-trust-anchor-identifiers
[checkpoint]: https://c2sp.org/tlog-checkpoint
[trust anchor IDs]: https://www.ietf.org/archive/id/draft-ietf-tls-trust-anchor-ids-04.html
[witness]: https://c2sp.org/tlog-witness

## Serving Issuance Logs

MTC CAs following this profile MUST serve issuance logs as
[tiled transparency logs][]. Each log's [prefix URL][] is the concatenation of
the CA prefix URL and the log number, encoded as an ASCII decimal integer with
no additional leading zeros:

```
<CA prefix URL>/<log number>
```

Each issuance log’s [checkpoint][] origin is its [log ID][] represented as an
origin, as described above. For example, log 42 of a CA with ID `32473.2` has a
log ID of `32473.2.0.42` and a checkpoint origin of
`oid/1.3.6.1.4.1.32473.2.0.42`.

Each issuance log MUST serve a checkpoint that includes a signature from its
[CA cosigner][], formatted as a [note signature][]. The CA cosigner is mapped to
a [transparency log cosigner][] as described below. Issuance logs MAY serve
additional cosignatures, including ones from cosigners that are not
[MTC cosigners][MTC cosigner].

If [pruned][], an issuance log MUST set its minimum index such that only expired
entries are pruned. Relying parties MAY set further restrictions, such as
requiring that an entry be expired for at least 6 months before pruning.

An issuance log with a landmark sequence MUST [publish active landmarks][] at
the following URL:

```
<CA prefix URL>/<log number>/landmarks
```

[CA cosigner]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.html#name-certification-authority-cos
[log ID]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.html#name-issuance-logs
[MTC cosigner]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.html#name-cosigners
[note signature]: http://c2sp.org/signed-note
[prefix URL]: https://c2sp.org/tlog-tiles#parameters
[pruned]: https://c2sp.org/tlog-tiles#pruning
[publish active landmarks]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.html#name-publishing-landmarks
[transparency log cosigner]: https://c2sp.org/tlog-cosignature

## Cosigners

An [MTC cosigner][] is mapped to a [transparency log cosigner][] as follows:

* The cosigner’s name is derived from the MTC cosigner’s ID as described above.
  For example, an MTC cosigner with ID `32473.3` has name
  `oid/1.3.6.1.4.1.32473.3`.

* The cosigner MUST use an ML-DSA-44 key and generate
  [ML-DSA-44 signed messages][], which are compatible with the MTC construction.
  This MAY be extended to future [MTC-compatible][], subtree-capable signed
  messages.

Conversely, a [witness][], [mirror][], or other transparency log cosigner whose
signatures are used in [standalone certificates][] MUST be an MTC cosigner. In
particular, it MUST have a cosigner name and key satisfying the above
requirements. It SHOULD implement the [`sign-subtree` endpoint][sign-subtree]
for CAs to request subtree signatures.

*TODO: Update the sign-subtree URL to tlog-witness when the PR is merged.*

An MTC CA’s [CA cosigner][] has the same ID as the CA, so a CA with ID `32473.2`
has a cosigner name of `oid/1.3.6.1.4.1.32473.2`. Note this is different from
the log origin.

An MTC CA operates a series of issuance logs, switching to the next log number
as needed for failure recovery. Witnesses and other non-CA cosigners SHOULD be
configured to accept the next few unused log numbers.

[mirror]: https://c2sp.org/tlog-mirror
[ML-DSA-44 signed messages]: https://c2sp.org/tlog-cosignature#ml-dsa-44-signed-message
[MTC-compatible]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.html#name-signature-format
[sign-subtree]: https://github.com/C2SP/C2SP/pull/245
[standalone certificates]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.html#name-standalone-certificates
