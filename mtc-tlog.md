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
non-critical X.509 extension with OID 1.3.6.1.4.1.64829.2.1 and syntax an
IA5String, as defined below. The IA5String's contents are the CA prefix URL.
Presence of this extension indicates that the certificate subject follows this
specification.

``` asn.1
id-mtcTlogPrefixURL OBJECT IDENTIFIER ::= {
    iso(1) org(3) dod(6) internet(1) private(4) enterprise(1) C2SP(64829)
    mtc-tlog(2) 1 }

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

Relying parties SHOULD set restrictions on [pruning][], such as requiring
that the log's minimum index be at most the minimum trusted index in
up-to-date copies of the relying party's trust anchors

An issuance log with a landmark sequence MUST [publish active landmarks][] at
the following URL:

```
<CA prefix URL>/<log number>/landmarks
```

This endpoint is mutable, but updates infrequently. Responses SHOULD
include a [`Cache-Control: max-age=<seconds>`][cache-control] header whose
value approximates the number of seconds the CA expects until it next
allocates a landmark. CAs SHOULD include a small buffer in this value to
ensure the next landmark is allocated before the cache expires, avoiding
unnecessary retries from clients waiting on it. A client waiting for a
future landmark can then re-fetch the resource after its cached copy
expires to pick up the latest landmark sequence.

[cache-control]: https://www.rfc-editor.org/rfc/rfc9111#section-5.2.2.1
[CA cosigner]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.html#name-certification-authority-cos
[log ID]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.html#name-issuance-logs
[MTC cosigner]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.html#name-cosigners
[note signature]: http://c2sp.org/signed-note
[prefix URL]: https://c2sp.org/tlog-tiles#parameters
[pruning]: https://c2sp.org/tlog-tiles#pruning
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

An MTC CA’s [CA cosigner][] has the same ID as the CA, so a CA with ID `32473.2`
has a cosigner name of `oid/1.3.6.1.4.1.32473.2`. Note this is different from
the log origin.

An MTC CA operates a series of issuance logs, switching to the next log number
as needed for failure recovery. Witnesses and other non-CA cosigners SHOULD be
configured to accept the next few unused log numbers.

[mirror]: https://c2sp.org/tlog-mirror
[ML-DSA-44 signed messages]: https://c2sp.org/tlog-cosignature#ml-dsa-44-signed-message
[MTC-compatible]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.html#name-signature-format
[sign-subtree]: https://c2sp.org/tlog-witness#sign-subtree
[standalone certificates]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.html#name-standalone-certificates

## Client-Constructed Landmark-Relative Certificates

Because each issuance log is served as a [tiled transparency log][tiled transparency logs],
an [authenticating party][] (or any other party) holding a
[standalone certificate][standalone certificates] can construct a
[landmark-relative certificate][] for the same entry by fetching data
directly from the issuance log, without any CA-specific issuance API
beyond what is already defined in this document.

The required inputs are:

* The standalone certificate itself. From it, the construction uses the
  [CA ID][] (the certificate's issuer) and the log number and entry index
  (encoded in the certificate's serial number as
  `(<log number> << 48) | <entry index>`; see
  [Certificate Format][certificate format]).
* The CA prefix URL of the issuance log. The CA conveys this URL to
  [MTC-aware ACME clients](#acme-issuance-for-mtc-aware-clients) at
  certificate issuance time, as described below. It may also be obtained
  from the CA's issuance-log X.509 extension (see
  [Parameters](#parameters)), or out of band. The CA prefix URL identifies
  the log's serving location as defined in
  [Serving Issuance Logs](#serving-issuance-logs).

Construction proceeds as follows:

1. Fetch the [landmarks file][publish active landmarks] from
   `<CA prefix URL>/<log number>/landmarks`.

2. Derive the landmark subtree and landmark number covering the entry index
   from the landmark sequence (see
   [Constructing Landmark-Relative Certificates][constructing landmark-relative]).

   If no active landmark covers the entry, the authenticating party cannot
   construct a landmark-relative certificate for it. This can happen because
   the entry is not yet covered by an allocated landmark, in which case the
   authenticating party SHOULD wait for the cached landmark file to expire,
   re-fetch it, and retry the construction. It can also happen because every
   landmark that once covered the entry has aged out of the active landmark
   window, in which case retrying will not help.

3. Fetch the [Merkle Tree tiles][merkle tree tiles] containing the hashes
   needed to generate the [subtree inclusion proof][] for the entry index
   in the landmark subtree, and generate the proof. A party that is aware
   of mirrors of the issuance log MAY fetch tiles from those mirrors
   instead of, or in addition to, the CA prefix URL; this document does
   not define a discovery mechanism for such mirrors.

4. [Construct the landmark-relative certificate][constructing landmark-relative]
   by copying every field of the standalone certificate, except for the
   `signatureValue`. The new `signatureValue` contains an
   [`MTCProof`][certificate format] whose `extensions` field is copied from
   the standalone certificate's `MTCProof`, whose `start`, `end`, and
   `inclusion_proof` describe the landmark subtree and the inclusion proof
   from above, and whose `signatures` field is empty.

5. Configure certificate selection for the resulting
   [landmark-relative certificate][] based on the CA ID, log number, and
   landmark number (see
   [Landmark-Relative Certificates in TLS][landmark-relative tls]).

The CA does not need to perform any per-client work to enable this flow: the
tiles and landmarks required are exactly those already published by every
issuance log conformant to this profile.

[authenticating party]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.html#name-terminology-and-roles
[CA ID]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.html#name-certification-authority-ide
[certificate format]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.html#name-certificate-format
[constructing landmark-relative]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.html#name-constructing-landmark-relat
[landmark-relative certificate]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.html#name-landmark-relative-certifica
[landmark-relative tls]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.html#section-8.2
[merkle tree tiles]: https://c2sp.org/tlog-tiles#merkle-tree
[subtree inclusion proof]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.html#name-subtree-inclusion-proofs

## ACME Issuance for MTC-Aware Clients

A CA following this profile and issuing certificates over [ACME][RFC 8555]
MUST convey its CA prefix URL to MTC-aware ACME clients at certificate
issuance time, so that the client can locate the issuance log. One use is
described in
[Client-Constructed Landmark-Relative Certificates](#client-constructed-landmark-relative-certificates).

An ACME client signals MTC-awareness by including an MTC media type in the
`Accept` header of its certificate-download request, as defined by the MTC
[ACME extension][acme extensions]. When such a request results in the CA
returning a [standalone certificate][standalone certificates], the response
MUST also carry a [Web Linking][RFC 8288] `Link` header field with link
relation type `c2sp.org/mtc-tlog/prefix-url`, whose target is the CA prefix
URL of the issuance log that contains the certificate's entry:

```
Link: <https://example-ca.com/mtc/>;rel="c2sp.org/mtc-tlog/prefix-url"
```

The target URL is a CA prefix URL as defined in [Parameters](#parameters),
and is identical to the value that would be carried in the CA's issuance-log
X.509 extension if such a certificate were used to represent the CA. The
target URL MAY be a URL of the same origin as the ACME server.

The response MUST NOT contain additional link relations of the same type.

This document does not require CAs to advertise any mirrors of the issuance
log. Clients that wish to fetch tiles from a mirror instead of from the CA
prefix URL obtain mirror URLs out of band.

[acme extensions]: https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-04.html#name-acme-extensions
[RFC 8288]: https://www.rfc-editor.org/rfc/rfc8288.html
[RFC 8555]: https://www.rfc-editor.org/rfc/rfc8555.html
