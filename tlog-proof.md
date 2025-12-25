# Transparency Log Proofs

This document describes a textual format for a an offline-verifiable proof that
some data has been logged to a transparency log and that its inclusion has been
observed by some number of witnesses.

More specifically, a proof composes the following information:

  - a [checkpoint][tlog-checkpoint] issued by the log, optionally including
    [cosignatures][tlog-cosignature] from [witnesses][tlog-witness];

  - the index of the entry in the log;

  - an Merkle inclusion proof for the entry at that index in the checkpointed
    tree;

  - optional opaque extra data, with application-specific meaning.

```
c2sp.org/tlog-proof@v1
extra YWdlLXYxLjIuMS1kYXJ3aW4tYXJtNjQudGFyLmd6kYXJ3aW4tYXJ
index 73894
gSKyXoYZUgZ6jduWYrkDOARinOMGJveXjgMkBTcdPlQ=
B95lDa8R83lS8n0eG+o0buTxRKQTYFi//1U8anccXmA=
EKNzoDWG8LGC0Yp9o+sv3qllpMP9uHQ9B20KNL+Q1zs=
RoopEkOdqkYqMB4MJXrbt/hMjOxsVn0IrWjpz1ZMMes=
AHCioX9nLjsrse6YhjRRmk1WUEirVOLLRoOQ6vfO5vk=

example.com/fancylog
109482
sFodV/vSp5O8n9a8QpW6PRY97tfOSW5bsc2Xl/EQi08=

— example.com/fancylog hI2DJw[...]1roloI=
— witness1.example mJirIklj[...]qY9v2B/5bg==
— witness2.example TnKKVHLX[...]xwYwrSjgow==
— witness3.example S4X82uH5[...]3oEcROGLFQ==
```

Proofs SHOULD be stored with file extension `.tlog-proof`.

Because proofs are self-contained and offline-verifiable against a fixed set of
data (the log's origin, and a policy of trusted log and witness public keys),
they fit the abstraction of detached digital signatures, and are sometimes
referred to as *transparent* or *spicy signatures*.

## Conventions used in this document

The base64 encoding used throughout is the standard Base 64 encoding specified
in [RFC 4648][], Section 4.

`U+` followed by four hexadecimal characters denotes a Unicode codepoint, to be
encoded in UTF-8.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][] [RFC 2119][] [RFC
8174][] when, and only when, they appear in all capitals, as shown here.

[RFC 4648]: https://www.rfc-editor.org/rfc/rfc4648.html
[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html

## Format

The proof is a sequence of lines separated by newlines (U+000A).

The first line MUST be the string `c2sp.org/tlog-proof@v1`.

The second line MAY start with the string `extra` followed by a space (U+0020)
and base64-encoded opaque extra data. If no extra data is present, this line is
omitted. Appications MUST NOT implicitly trust the extra data, as it is not
authenticated. (Use cases for the extra data include out-of-band context, or
additional data necessary to reconstruct the record hash, such as a VRF proof.)

The next line MUST start with the string `index` followed by a space (U+0020)
and the zero-based index of the entry in the log, represented as an ASCII
decimal with no leading zeroes (unless the index is `0`).

The next zero or more non-empty lines are the base64-encoded Merkle inclusion
proof for the entry at the specified index in the checkpointed tree, one SHA-256
hash per line, starting from the leaf's sibling hash up to the root's child
hash. See [RFC 6962, Section 2.1.1] for the precise format.

After the inclusion proof lines and an empty line, the checkpoint issued by the
log is included verbatim, according to [tlog-checkpoint][].

[tlog-checkpoint]: https://c2sp.org/tlog-checkpoint
[tlog-cosignature]: https://c2sp.org/tlog-cosignature
[tlog-witness]: https://c2sp.org/tlog-witness
[RFC 6962, Section 2.1.1]: https://www.rfc-editor.org/rfc/rfc6962.html#section-2.1.1

## Verifying a tlog proof

To verify a tlog proof, as defined above, the verifier needs
additional information: It needs to know the contents of the leaf that
is logged (based on application-specific data provided out-of-band,
and the `extra` line; e.g., this could include the hash of a software
artifact and metadata). The verifier also needs the public keys for
origin lines it is willing to accept, as well as the public keys for
some witnesses.

To verify the proof, the following steps are required:

1. Compute the leaf hash. This step is application specific.

2. Check that the checkpoint origin line is acceptable, and that the
   checkpoint is signed by a log public key configured for that origin
   line.

3. Verify all cosignatures for witnesses known to the verifier. Which
   subsets of witnesses are considered strong enough, is determined by
   application policy. One possible policy is to require k valid
   cosignatures out of n known witnesses; more complex policies are
   possible but out of scope for this document.

4. Check that the inclusion proof is valid, to bind the leaf hash
   computed in step 1 to the the root hash of the signed checkpoint.

### Use of timestamps

Each cosignature timestamp is covered by the corresponding witness
cosignature, and hence are required to be able to verify the
cosignature. However, after a cosignature has been verified, the
timestamp value is ignored by the above verification procedure.
Application policy may apply additional constraints on the timestamps.
