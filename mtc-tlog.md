---
description: A profile of Merkle Tree Certificates (MTCs) that uses tiled transparency logs
---

> [!WARNING]
> This is the editor's copy of this specification.
> For a stable rendered reference, use [c2sp.org/mtc-tlog](https://c2sp.org/mtc-tlog).

# Merkle Tree Certificates With Tiled Transparency Logs

This document defines a profile of [Merkle Tree Certificates][] (MTCs) that uses
[tiled transparency logs][].

[Merkle Tree Certificates]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-08.html
[tiled transparency logs]: https://c2sp.org/tlog-tiles@v1.0.0

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
in the MTC specification, one or more *CA prefix URLs*. Each CA prefix URL
determines a set of serving URLs for the CA's issuance logs, as described below.

When such a CA is [represented as an X.509 certificate][], the certificate has a
non-critical X.509 extension with OID 1.3.6.1.4.1.64829.2.2 and syntax a
SEQUENCE OF IA5String, as defined below. Each IA5String's contents are one of
the CA prefix URLs. Presence of this extension indicates that the certificate
subject follows this specification.

``` asn.1
id-mtcTlogPrefixURLs OBJECT IDENTIFIER ::= {
    iso(1) org(3) dod(6) internet(1) private(4) enterprise(1) C2SP(64829)
    mtc-tlog(2) 2 }

MTCTlogPrefixURLs ::= SEQUENCE SIZE (1..MAX) OF IA5String

ext-mtcTlogPrefixURLs EXTENSION ::= {
    SYNTAX MTCTlogPrefixURLs
    IDENTIFIED BY id-mtcTlogPrefixURLs
    CRITICALITY FALSE
}
```

[Tiled transparency logs][tiled transparency logs] are currently only defined
with SHA-256, so MTC CAs following this profile MUST use SHA-256 as the hash
algorithm.

[CA parameters]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-08.html#name-certification-authorities
[represented as an X.509 certificate]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-08.html#name-representing-certification-

## Representing Trust Anchor IDs

MTC entities are named using [trust anchor IDs][]. This section defines how to
map these to [log origins and cosigner names][]. A trust anchor ID is
represented as the concatenation of:

* The 16-byte ASCII string `oid/1.3.6.1.4.1.`, including the trailing period
* The trust anchor ID's [ASCII representation][]

This is equivalent to the concatenation of:

* The four-byte ASCII string `oid/`
* The trust anchor ID as a full OID, in dotted decimal notation

For example, the trust anchor ID `32473.1` is represented as
`oid/1.3.6.1.4.1.32473.1`.

[ASCII representation]: https://www.ietf.org/archive/id/draft-ietf-tls-trust-anchor-ids-06.html#name-trust-anchor-identifiers
[trust anchor IDs]: https://www.ietf.org/archive/id/draft-ietf-tls-trust-anchor-ids-06.html
[log origins and cosigner names]: https://c2sp.org/tlog-cosignature@v1.1.0#cosigners

## Serving Issuance Logs

MTC CAs following this profile MUST serve issuance logs as
[tiled transparency logs][]. Each log's [prefix URLs][] are determined by
concatenating the log number, encoded as an ASCII decimal integer with no
additional leading zeros, to each CA prefix URL:

```
<CA prefix URL>/<log number>
```

Each issuance log’s origin is its [log ID][] represented as described above.
For example, log 42 of a CA with ID `32473.2` has a
log ID of `32473.2.0.42` and a log origin of `oid/1.3.6.1.4.1.32473.2.0.42`.

Each issuance log MUST serve a [checkpoint][] that includes a signature from its
[CA cosigner][], formatted as a [note signature][]. The CA cosigner is mapped to
a [transparency log cosigner][] as described below. Issuance logs MAY serve
additional cosignatures, including ones from cosigners that are not
[MTC cosigners][MTC cosigner].

Relying parties SHOULD set restrictions on [pruning][], such as requiring
that the log's minimum index be at most the minimum trusted index in
up-to-date copies of the relying party's trust anchors.

### Landmarks

For each CA prefix URL, an issuance log with a [landmark sequence][] MUST
publish its active landmarks at the following URL:

```
<CA prefix URL>/<log number>/landmarks
```

The content type MUST be `text/plain; charset=utf-8`. The content MUST be a
sequence of lines, each terminated by a newline character (U+000A), as follows:

* A header line consisting of a decimal integer, `latest_landmark`, with the
  landmark number of the log's most recent landmark at the time of publishing.
  This value MUST be at most 2<sup>48</sup>-1.

* A sequence of `num_active_landmarks + 1` lines, where `num_active_landmarks`
  is the number of active landmarks at the time of publishing. Decoders MUST
  reject documents where there are greater than `latest_landmark + 1` such
  lines. Numbered consecutively from zero, line `i` in this sequence consists
  of:

  * The tree size for landmark `latest_landmark - i` as a decimal integer. This
    value MUST be at most 2<sup>48</sup>-1.
  * A single space character (U+0020).
  * The expiration time for landmark `latest_landmark - i` as a decimal integer
    containing [seconds since the Epoch][].

Tree sizes MUST be strictly monotonically decreasing, and expiration times MUST
be monotonically decreasing. There MUST be at least one expiration time before
the current time.

Decoders MUST reject documents that do not strictly conform to the above
requirements, including extraneous whitespace and the lack of an expired
landmark. A decoder MAY process only a prefix of this document, provided there
is at least one expired landmark to denote the end of the active landmarks.

Most deployments obtain landmark-relative certificates directly from the CA.
Alternatively, a party holding a [standalone certificate][standalone certificates]
can construct the corresponding [landmark-relative certificate][] by following
the generic [construction procedure][constructing landmark-relative]. The
landmark sequence is available at the URL above, and the required inclusion
proof hashes are available from the log's [Merkle Tree tiles][merkle tree tiles].

[constructing landmark-relative]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-08.html#name-constructing-landmark-relat
[landmark-relative certificate]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-08.html#name-landmark-relative-certifica
[merkle tree tiles]: https://c2sp.org/tlog-tiles@v1.0.0#merkle-tree
[CA cosigner]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-08.html#name-certification-authority-cos
[log ID]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-08.html#name-issuance-logs
[MTC cosigner]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-08.html#name-cosigners
[note signature]: https://c2sp.org/signed-note@v1.1.0
[prefix URLs]: https://c2sp.org/tlog-tiles@v1.0.0#parameters
[pruning]: https://c2sp.org/tlog-tiles@v1.0.0#pruning
[landmark sequence]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-08.html#name-landmark-tree-sizes
[seconds since the Epoch]: https://pubs.opengroup.org/onlinepubs/9799919799/basedefs/V1_chap04.html#tag_04_19
[transparency log cosigner]: https://c2sp.org/tlog-cosignature@v1.1.0
[checkpoint]: https://c2sp.org/tlog-checkpoint@v1.1.0

## Cosigners

An [MTC cosigner][] is mapped to a [transparency log cosigner][] as follows:

* The cosigner name is derived from the MTC cosigner’s ID as described above.
  For example, an MTC cosigner with ID `32473.3` has name
  `oid/1.3.6.1.4.1.32473.3`.

* The MTC cosigner MUST generate cosignatures with ML-DSA-44, defined in
  [RFC 9881][]. The transparency log cosigner is then an [ML-DSA-44 cosigner][],
  which is compatible with the MTC signature format. This MAY be extended to
  future [MTC-compatible][], subtree-capable cosigners.

Conversely, a [witness][], [mirror][], or other transparency log cosigner whose
subtree cosignatures are used in [standalone certificates][] MUST have a
cosigner name satisfying the above requirements. It SHOULD implement the
[`sign-subtree` endpoint][sign-subtree] for CAs to request subtree signatures.

An MTC CA’s [CA cosigner][] has the same ID as the CA, so a CA with ID `32473.2`
has a cosigner name of `oid/1.3.6.1.4.1.32473.2`. Note this is different from
the log origin.

An MTC CA operates a series of issuance logs, switching to the next log number
as needed for failure recovery. Witnesses and other non-CA cosigners SHOULD be
configured to accept the next few unused log numbers.

[witness]: https://c2sp.org/tlog-witness@v1.1.0
[mirror]: https://c2sp.org/tlog-mirror@v0.1.0
[RFC 9881]: https://www.rfc-editor.org/info/rfc9881/
[ML-DSA-44 cosigner]: https://c2sp.org/tlog-cosignature@v1.1.0#ml-dsa-44
[MTC-compatible]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-08.html#name-signature-format
[sign-subtree]: https://c2sp.org/tlog-witness@v1.1.0#sign-subtree
[standalone certificates]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-08.html#name-standalone-certificates
