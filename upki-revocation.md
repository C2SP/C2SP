# UPKI Revocation

This document specifies the on-disk data structures and check procedure used to
perform offline TLS certificate revocation checks against a local cache of
Mozilla [CRLite][] filters encoded in the [clubcard][] v4 format, distributed by
[upki][]. It is aimed at implementors of clients that consume such a cache
in order to consult it for efficient revocation decisions during certificate
path validation.

The cache consists of one or more encoded clubcard filter files together with a
binary index that maps `(CT log ID, SCT timestamp)` pairs to the covering
filter files in the cache. Given an end-entity certificate and its
embedded [SCTs][RFC 6962], an implementation can determine one of four
outcomes: **revoked**, **not revoked**, **not enrolled**, or **not covered**
using the available revocation data.

How the cache is populated (e.g. production, hosting, downloading, verification,
and incremental update of CRLite clubcard data) is out of scope for this
document.

[CRLite]: https://blog.mozilla.org/security/2020/01/09/crlite-part-2-end-to-end-design/
[clubcard]: https://github.com/mozilla/clubcard
[upki]: https://github.com/rustls/upki

## Conventions used in this document

Data structures are described using notation inspired by Section 3 of
[RFC 8446][]. This document deviates from RFC 8446 in one respect:
length-prefixed sequences of composite types carry an **element count** rather
than a byte length, and are written in the form

```
    uintN count;
    T     items[count];
```

where the leading `count` field is on the wire. `opaque x[N]` retains its RFC
8446 meaning of a fixed-length byte string of exactly `N` bytes. `opaque
x<A..B>` retains its RFC 8446 meaning of a variable-length byte string prefixed
by a byte-length field wide enough to encode `B`; for opaque byte strings this
length is equivalently a count of bytes and of elements.

All integer fields are unsigned and encoded in **big-endian** order.

`0x` followed by two hexadecimal characters denotes a byte value in the 0–255
range. 

`||` denotes concatenation. 

`SHA-256(x)` denotes the SHA-256 digest of `x` as specified in [FIPS 180-4][],
producing a 32-byte value.

The **SPKI hash** of a certificate is the SHA-256 digest of the DER encoding of
its `SubjectPublicKeyInfo` field, as defined in [RFC 5280][].

The **serial number** of a certificate is the DER-encoded contents (i.e. the
`INTEGER` value bytes, excluding tag and length) of the end-entity certificate's
`serialNumber` field, as specified in [RFC 5280][] §4.1.2.2. Importantly, if the
DER encoding includes a leading `0x00` byte to disambiguate the sign, that byte
is retained when used as a revocation input.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][] [RFC 2119][] [RFC
8174][] when, and only when, they appear in all capitals, as shown here.

[RFC 8446]: https://www.rfc-editor.org/rfc/rfc8446.html
[RFC 6962]: https://www.rfc-editor.org/rfc/rfc6962.html
[RFC 5280]: https://www.rfc-editor.org/rfc/rfc5280.html
[FIPS 180-4]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf
[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html
[Schanck 2025]: https://doi.org/10.1109/SP61157.2025.00128

## Introduction

CRLite is a scheme for compactly representing the set of revoked
publicly-trusted TLS certificates so that a client can answer "is this
certificate revoked?" locally, without contacting a certificate authority or
OCSP responder. It is space efficient compared to independent CRL files, leaks
no private information to the CRL/OCSP issuer, and can support the scale of the
Web PKI. In its current form the compact representation is a set membership data
structure, a **clubcard filter**, combined with metadata describing the subset
of the Web PKI it covers.

A single clubcard filter does not cover the whole Web PKI. Each filter is
scoped to a specific set of CT logs and a specific window of SCT timestamps
within those logs. In practice, a client maintains a **revocation cache
directory** containing several filter files whose scopes together cover the
CT logs and time ranges the client cares about. A given certificate's SCTs
determine which filters, if any, must be consulted. Filter scopes may overlap,
so a single certificate can be covered by more than one filter, and a conclusive
answer can come from any covering filter, so each must be consulted.

Selecting the covering filters efficiently is the job of a binary index file
(`index.bin`) that sits alongside the filters in the cache. The index maps
each `(CT log ID, SCT timestamp)` pair a client might see to the names of the
filter files that cover it, so a query need not open or parse any filter file
that cannot contribute to the answer. The client then parses each covering
filter file, performs a clubcard query against it, and aggregates the
per-filter results to determine whether the certificate is revoked.

A clubcard is a two-stage filter based on solving systems of linear equations
over `GF(2)`. The construction, its parameters, and the query algorithm are
specified in [Schanck 2025][] and this document does not restate them. Where the
on-disk structures defined here carry values that parameterize a clubcard
query, they are described as inputs to the algorithm in that paper.

Operationally, a deserialized clubcard combines three pieces of data. An
**approximate filter** is a compact bit matrix that, for most queries, quickly
rules the key out of the encoded set. An **exact filter** is a second, denser
structure consulted for keys the approximate filter does not rule out. Together
the two structures exactly reproduce the membership of the set the filter was
built from. Lastly, an **exception list** carries the small number of lookup
keys that the linear-system construction could not encode, and whose membership
is answered by direct lookup. The wire format in this document carries one
approximate filter, one exact filter, and a per-issuer exception list.

This document specifies:

- The version 4 wire format of clubcard-encoded CRLite filter files.
- The layout of a cache directory containing one or more such filters.
- The version "upkiidx1" upki binary index (`index.bin`) that maps `(CT log ID,
  SCT timestamp)` pairs to the filter files that cover them.
- The general procedure a client follows to select the filters covering
  a given certificate, query each of them, and combine the results, deferring
  to [Schanck 2025][] for the query itself.

Filter versions 0 through 3 predate this specification and are not covered
here. An implementation of this specification MAY reject filters whose
version identifier is not 4.

## Clubcard Parameters

A general clubcard implementation is parameterized and for this specification
and the CRLite context we fix the parameters to the following concrete values:

- **Hash function** `H`. We select `H = SHA-256`, producing a 32-byte digest.
- **Log identifier length** `L_id`. We select `L_id = 32` bytes, matching the CT
  `LogID` defined in Section 3.2 of [RFC 6962][]. Concretely this is the SHA-256
  digest of a log's public key.
- **Clubcard query width** `W`. We select `W = 4`. Each query is expressed as
  a linear equation over `W` distinct 64-bit lanes, i.e. 256 bits wide.

## Filter file format

A single filter file within the revocation data cache is a self-contained
encoding of a single clubcard together with the CRLite metadata needed to
interpret it:

* the CT logs it covers,
* the timestamp intervals within those logs,
* and the per-issuer parameters that let a client query it.

The top-level structure is:

```
    struct {
        uint8 version;
        uint8 reserved0;
        CRLiteCoverage coverage;
        ClubcardIndex index;
        ApproximateFilter approximate;
        ExactFilter exact;
    } FilterFile;
```

The `version` value MUST be 4. An implementation MAY reject a file whose
`version` is not 4.

The `reserved0` byte MUST be `0x00`. An implementation MUST reject a file whose
`reserved0` is not zero. Future versions of the format may use a non-zero value
to signal the presence of additional metadata (e.g. describing a partition of
the filter) that is omitted in version 4.

### Coverage

The `CRLiteCoverage` structure enumerates the CT logs and timestamp ranges
that were included when the filter was built. A query that is not scoped to at
least one covered `(LogID, timestamp)` pair yields **not covered** for this
filter (see [Revocation check procedure](#revocation-check-procedure)).

```
    opaque LogID[32];

    struct {
        uint64 low;                 /* inclusive, milliseconds since Unix epoch */
        uint64 high;                /* inclusive, milliseconds since Unix epoch */
    } TimestampInterval;

    struct {
        LogID log_id;
        TimestampInterval interval;
    } CoverageEntry;

    struct {
        uint16        count;
        CoverageEntry entries[count];
    } CRLiteCoverage;
```

Each `CoverageEntry` is exactly 48 bytes on the wire. Entries MUST have
distinct `log_id` values. Their order is not significant.

Timestamps are non-negative integers denoting milliseconds since
`1970-01-01T00:00:00Z` ignoring leap seconds, as used by [RFC 6962][] SCTs.

### Per-issuer index

The `ClubcardIndex` maps each covered certificate issuer, identified by its
32-byte SPKI hash, to the parameters needed to query the clubcard filter for
serial numbers issued by that issuer. An issuer absent from this index was
not enrolled in the filter when it was built and queries for such an issuer
yield **not enrolled** (see [Revocation check
procedure](#revocation-check-procedure)).

```
    opaque IssuerSPKIHash[32];

    opaque Exception<1..2^8-1>;

    struct {
        uint32    approx_m;            /* rows in the approximate matrix */
        uint8     approx_rank;         /* columns in the approximate matrix */
        uint32    approx_offset;       /* row offset into the approximate matrix */
        uint32    exact_m;             /* rows in the exact matrix */
        uint32    exact_offset;        /* row offset into the exact matrix */
        uint8     inverted;            /* 0 or 1; result inversion flag */
        uint16    exception_count;
        Exception exceptions[exception_count];
    } IssuerBlock;

    struct {
        IssuerSPKIHash issuer;
        IssuerBlock    block;
    } IssuerEntry;

    struct {
        uint32      count;
        IssuerEntry entries[count];
    } ClubcardIndex;
```

The `IssuerEntry` list MUST be sorted lexicographically by `issuer` and MUST
NOT contain duplicate `issuer` values. Sorting permits a binary search when
locating the block for a given issuer during a query, and the sorted order is
part of the wire format. An implementation that writes filter files MUST
sort, and an implementation that reads filter files MAY assume sorted order.

The `exceptions` list contains certificate serial numbers, each as a
variable-length opaque byte string, that a builder could not encode via the
linear system and therefore stores explicitly. Each serial is prefixed by a
single byte giving its length in bytes, so an individual exception serial is
at most 255 bytes.

Each field of `IssuerBlock` is an input to the clubcard query defined in
[Schanck 2025][]. `approx_m`, `approx_rank`, and `approx_offset` parameterize
the query into the approximate filter for this issuer's block. `exact_m` and
`exact_offset` parameterize the query into the exact filter. `inverted` is
a per-block polarity flag and MUST be either 0 or 1. `exceptions` is the
block's exception list, and each entry a variable-length certificate serial
number. Implementations MUST reject a filter file whose `inverted` value is not
0 or 1.

### Approximate filter

Conceptually, the approximate filter is a large bit matrix `X` that is
a solution to a homogeneous matrix equation `A * X = 0` derived from the encoded
revocation set ([Schanck 2025][]). `X` is shared by every `IssuerEntry` in the
same `ClubcardIndex` and each issuer block's queries read the leading
`approx_rank` columns of `X`, anchored within the `approx_m` consecutive rows
starting at row `approx_offset` of that block.

On the wire, `X` is stored as a sequence of columns:

```
    struct {
        uint32 word_count;
        uint64 words[word_count];   /* each word is a big-endian uint64 */
    } BitColumn;

    struct {
        uint8     count;
        BitColumn columns[count];
    } ApproximateFilter;
```

Bits within a `BitColumn` are indexed from 0 starting at the least significant
bit of `words[0]`. That is, bit `i` (`0 <= i < 64 * word_count`) lives at
`words[i / 64] >> (i % 64) & 1`. Bits at indices beyond `64 * word_count - 1`
are **implicitly equal to 0**. A query can depend on bits that are not encoded
in the `BitColumn`, so an implementation MUST evaluate such bits as 0.

Only the region of `X` that can hold non-zero bits is explicitly encoded.
Column `i` of `X` is read only by blocks whose `approx_rank` is greater than
`i`, which shapes the encoding as follows:

- `count` equals the largest `approx_rank` across all issuer blocks in the
  `ClubcardIndex`. An implementation MUST treat a filter file in which any
  block's `approx_rank` exceeds `count` as malformed.

- Column `i` explicitly encodes rows only up to the largest value of
  `approx_offset + approx_m` among blocks with `approx_rank > i`. Builders
  assign smaller `approx_offset` values to blocks with larger `approx_rank`,
  so the explicitly encoded region of `X` has a staircase shape where successive
  columns cover progressively fewer rows.

- A builder MAY further omit trailing all-zero words from any column. Each
  `BitColumn` therefore carries its own `word_count`. A reader MUST NOT
  assume any relationship between the `word_count` values of different
  columns, or between a column's `word_count` and any block's
  `approx_offset + approx_m`.

A block's query evaluates one 256-bit-wide linear equation (the query width
`W = 4`, in 64-bit lanes) against each of the block's leading `approx_rank`
columns. Each evaluation reads a rectangle of bits spanning rows
`[s, s + 256)` of columns `0` through `approx_rank - 1`, where `s` is a row
derived from the query key satisfying
`approx_offset <= s < approx_offset + approx_m`. The rectangle may extend
past the explicitly encoded words of a column and bits read there are implicitly
zero, as described above.

### Exact filter

The exact filter is a single column with the same encoding as one `BitColumn`
of the approximate filter:

```
    struct {
        uint32 word_count;
        uint64 words[word_count];
    } ExactFilter;
```

Bits are indexed within `words` in the same manner as an approximate filter
`BitColumn`, including the implicit-zero rule.

## Revocation cache directory layout

A conforming implementation reads revocation data from a directory (the
**revocation cache directory**) with the following layout:

```
    <revocation-cache-dir>/
        index.bin
        <clubcard-filter-file-1>
        <clubcard-filter-file-2>
        ...
```

`index.bin` is the [Index file format](#index-file-format), described below,
and identifies the filter files by name.

Filter files are ordinary files whose bytes conform to the [Filter file
format](#filter-file-format). Their names MUST be at most 32
bytes when encoded as UTF-8 and MUST NOT contain the byte `0x00` for
compatibility with the index file format. Beyond those restrictions, filenames
are opaque to this specification.

There MAY be additional metadata files in the cache directory (e.g.
`manifest.json`) that describes when the filters were fetched, their expected
checksums, etc. These details are outside of the scope of this specification and
are not required for efficient revocation checking.

Populating the cache directory, obtaining `index.bin` and the filter files
it names, verifying their integrity, and deciding when and how to refresh them
is out of scope for this document.

## Cache atomicity

Cache updates may happen concurrently with revocation checks. While cache
population is out of scope this section describes the contract between the
process populating the cache and the process reading from it, so that a check in
flight during an update doesn't encounter inconsistent results.

A conforming reader relies on the following invariants from whatever process
populates the cache:

1. Each individual file in the cache directory (`index.bin` and each filter
   file) MUST be replaced atomically. The new bytes must appear at the file's
   path in a single filesystem operation, with no observable intermediate state
   in which the path resolves to a truncated or partially-written file. On POSIX
   systems this is typically achieved by writing to a temporary file in the same
   directory and renaming after writing the data.

2. Before an `index.bin` referencing a filter file is added to the cache, the
   filter file bytes MUST be written to disk first, before any `index.bin` that
   references it becomes visible at `index.bin`'s path.

3. When a filter file is removed from the cache, its removal MUST NOT be
   observable until after an `index.bin` that no longer references it has become
   visible at `index.bin`'s path.

Together, these invariants ensure that any `index.bin` a reader may observe
references only filter files that are present in the cache directory at the
moment `index.bin` becomes visible.

The reader relies on these invariants during a check:

1. When a check begins, the reader opens `index.bin` and SHOULD hold the
   resulting file handle open for the entire duration of the check. On POSIX
   systems the handle keeps the underlying inode alive after a subsequent rename
   replaces the file at `index.bin`'s path, so on-demand reads of entry sections
   through the handle remain consistent with the header and tables the reader
   parsed at open time. New `index.bin` contents won't be read until the handle
   is closed and re-opened by its path for subsequent checks.

2. Filter files are opened by name after index lookup and not through a handle
   held from the start of the check. Opening a filter file therefore resolves
   against whatever bytes are currently visible at that filename. When the
   reader's `index.bin` handle still refers to the version of `index.bin`
   visible when the check began, the invariants above guarantee that the
   referenced filter file was present at that moment.

3. If opening a filter file identified in step 1 of the check procedure fails
   because the file does not exist, the reader MUST treat this as evidence that
   the `index.bin` it is using has been superseded by a newer one that no
   longer references the missing filter. The reader SHOULD retry the check
   from the beginning, reopening `index.bin` at least once before returning an
   error. An implementation MAY bound the number of retries to avoid unbounded
   restart under pathological update patterns.

## Index file format

The `index.bin` file is a binary lookup table. It maps `(LogID, timestamp)`
pairs to the filter files that cover them, storing enough metadata to select the
covering filter files for a query without loading each filter file into memory.
It is designed for memory-mapped or seek-based access: an implementation can
load the header and the two tables once, then use file offsets to fetch per-log
data on demand.

### High-level structure

```
    struct {
        Header header;
        FilenameEntry filenames[header.num_filenames];
        LogDirEntry   log_directory[header.num_log_ids];
        opaque        entry_sections[];
    } IndexFile;
```

`entry_sections` is a variable-length region containing one contiguous run of
per-log entries for each entry in `log_directory`, addressed by the `offset`
field of that entry. Its total length is determined implicitly by the file
size and the offsets in the log directory.

### Header

```
    struct {
        opaque magic[8];            /* MUST be "upkiidx1" */
        uint16 num_filenames;
        uint32 num_log_ids;
    } Header;
```

The `Header` is exactly 14 bytes. An implementation MUST reject a file whose
first 8 bytes are not the literal ASCII string `upkiidx1` (`0x75 0x70 0x6b 0x69
0x69 0x64 0x78 0x31`).

The `num_filenames` field limits the cache to at most 65535 filter files
addressable by a single index. `num_log_ids` gives the number of CT logs
covered by this index across all filter files.

### Filename table

```
    struct {
        opaque name[32];            /* UTF-8, zero-padded to 32 bytes */
    } FilenameEntry;
```

The filename table is `32 * num_filenames` bytes long and begins immediately
after the header, at file offset 14.

Each `name` slot holds a filter file's name as UTF-8, padded with `0x00`
bytes to 32 bytes total. There is no explicit length field; the actual name
is the byte prefix up to (but not including) the first `0x00`, or all 32
bytes if none is present. A well-formed filter file name MUST NOT contain
the byte `0x00`.

The position of a name in this table is its **filename index**, a `uint16`
value in the range `[0, num_filenames)`. Entry sections (defined below) refer
to filenames by this index rather than by name.

### Log directory

```
    struct {
        LogID  log_id;
        uint64 offset;       /* file offset, in bytes, to this log's entry section */
        uint16 num_entries;  /* number of Entry values in that section */
    } LogDirEntry;
```

The log directory is `42 * num_log_ids` bytes long and immediately follows
the filename table.

Entries MUST be sorted lexicographically by `log_id` as raw 32-byte
strings, matching the clubcard file format index sort. This ordering permits
a binary search when resolving a `LogID`. Duplicate `log_id` values MUST NOT
appear.

The `offset` field is measured from the start of the file. The referenced
entry section MUST lie entirely within the file and MUST NOT overlap the
header, filename table, or log directory. Overlap between distinct logs'
entry sections is unspecified and implementations SHOULD reject files where
it occurs.

### Entry sections

Each log's entry section is a packed sequence of `Entry` values:

```
    struct {
        uint16 filter_idx;          /* index into the filename table */
        uint64 min_timestamp;       /* inclusive, milliseconds since Unix epoch */
        uint64 max_timestamp;       /* inclusive, milliseconds since Unix epoch */
    } Entry;
```

An `Entry` is exactly 18 bytes. A log's entry section is `18 * num_entries`
bytes, where `num_entries` is the value in the corresponding `LogDirEntry`.

An `Entry` asserts that the filter named by `filenames[filter_idx]` covers
the corresponding `LogID` for SCT timestamps `t` satisfying
`min_timestamp <= t <= max_timestamp`.

Multiple entries for the same log MAY describe overlapping or adjacent intervals
covered by different filter files. When more than one entry matches a query
timestamp, every matching entry identifies a covering filter and the check
procedure consults all of them: a covering filter that cannot answer for a
certificate's issuer must not mask another covering filter that can (see
[Revocation check procedure](#revocation-check-procedure)).

`filter_idx` MUST be strictly less than `num_filenames`. An implementation
MUST treat a file containing an out-of-range `filter_idx` as malformed.

## Revocation check procedure

Given an end-entity certificate to check, and its issuer certificate, an
implementation determines the end-entity certificate revocation status by
consulting the cache directory as follows.

Several filters may cover the certificate's SCTs, and a covering filter is not
necessarily conclusive since it may not describe the certificate's issuer at
all. The procedure therefore locates every covering filter (step 1), queries
each one (step 2), and aggregates the per-filter outcomes into an overall result
(step 3).

### Inputs

The implementation extracts the following from the end-entity certificate under
evaluation and its issuing certificate:

- `issuer_spki_hash`: the [SPKI hash](#conventions-used-in-this-document) of
  the certificate that issued the end-entity certificate. This is a 32-byte
  value.
- `serial`: the DER encoded [serial number](#conventions-used-in-this-document)
  of the end-entity certificate (with leading `0x00` byte from DER encoding if
  applicable).
- `scts`: the list of Signed Certificate Timestamps embedded in the
  end-entity certificate under the extension defined in Section 3.3 of [RFC
  6962][]. Each SCT contributes a `(LogID, timestamp)` pair. Timestamps are
  treated as `uint64` milliseconds since Unix epoch, ignoring leap seconds, as
  they appear on the wire.

Detached SCTs delivered via TLS handshake or OCSP in place of an extension in
the end-entity certificate MAY be accepted as inputs at the implementation's
discretion. An implementation that accepts detached SCTs MUST validate their
signatures against the keys of CT logs it trusts before using them as inputs.
Unlike embedded SCTs, detached SCTs are not covered by the certificate
signature, and fabricated `(LogID, timestamp)` pairs could otherwise steer the
revocation check away from a filter that would otherwise report **revoked**.
Implementations SHOULD also validate the signatures on embedded SCTs as part of
evaluating their own certificate transparency policies during path validation.

If the certificate is not presented with any SCTs, the implementation SHOULD
return **not covered** without consulting the index or cached filters.

### Step 1: locate the covering filters

1. Open `index.bin` and keep the resulting file handle open for the duration
   of the check, as required by [Cache atomicity](#cache-atomicity). Read and
   validate the header according to the index [Header](#header) specification.
   Read the filename table and the log directory into memory according to the
   index [Log directory](#log-directory) specification.

2. For each `(log_id, timestamp)` pair in `scts`, in the order they appear
   in the certificate:

   a. Binary-search the index log directory for `log_id`. If not found, continue
      with the next SCT.

   b. Read the log's entry section from the index using the `offset` and 
      `num_entries` fields of the matching `LogDirEntry`.

   c. Scan the index entries in order. Every entry satisfying
      `min_timestamp <= timestamp <= max_timestamp` identifies a covering
      filter, whose filename relative to the cache directory is
      `filenames[filter_idx]` from the index [Filename
      table](#filename-table). Collect each such filename. An
      implementation MUST NOT stop at the first match.

3. If no SCT yields any covering filter, return **not covered**.

The filenames collected across all SCTs are the check's **covering filters**.

### Step 2: query each covering filter

For each covering filter from step 1, open the filter file from the revocation
directory using its relative filename and parse it as specified in [Filter
file format](#filter-file-format). If a filter file cannot be opened because
it does not exist, retry the check from step 1 as required by [Cache
atomicity](#cache-atomicity).

Implementations MAY wish to query covering filters in the order that they were
published since revocations are more likely shortly after certificate issuance.

Querying a filter yields one of **revoked**, **not revoked**,
**not enrolled**, or **not covered** for that filter, as follows:

1. Verify that at least one SCT in `scts` is covered by the filter's
   `CRLiteCoverage`. A `(log_id, timestamp)` pair is covered when a
   `CoverageEntry` exists whose `log_id` equals `log_id` and whose interval
   satisfies `low <= timestamp <= high`. If no SCT is covered, the filter
   yields **not covered**.

2. Locate the `IssuerEntry` in the filter's `ClubcardIndex` whose `issuer`
   equals `issuer_spki_hash`. If none exists, the filter yields
   **not enrolled**: the filter covers a relevant timestamp window but was
   built without data for this issuer. Note that because the coverage check
   precedes the issuer lookup **not enrolled** is only reported by a filter that
   covers at least one of the certificate's SCTs.

3. Query the clubcard on the key `SHA-256(issuer_spki_hash || serial)`,
   with the query-width parameter `W = 4`, using the located `IssuerBlock`
   fields (`approx_m`, `approx_rank`, `approx_offset`, `exact_m`,
   `exact_offset`, `inverted`, and `exceptions`) as the query inputs, and
   the filter's `ApproximateFilter` and `ExactFilter` as the underlying bit
   columns, as specified in [Schanck 2025][].

4. The filter yields **revoked** if the clubcard query reports the key as a
   member of the encoded set, otherwise it yields **not revoked**.

### Step 3: aggregate the per-filter results

With a per-filter outcome from step 2 in hand for every covering filter,
determine the check's overall result:

1. If any covering filter yielded **revoked**, return **revoked**.

2. Otherwise, if any covering filter yielded **not revoked**, return
   **not revoked**.

3. Otherwise, if every covering filter yielded **not enrolled**, return
   **not enrolled**.

An individual filter that yields **not covered** says nothing about the
certificate's revocation status and a filter that cannot answer for the
certificate's issuer or timestamps must not mask another covering filter that
can.

An individual filter that yields **not enrolled** indicates that the
certificate's issuer was not enrolled in the revocation data even though its
timestamps were covered. Implementations that make no policy distinction between
the two MAY collapse them, treating it as a **not covered** result. Like **not
covered**, this should not preclude checking other covering filters.

Because **revoked** takes precedence over every other outcome, an
implementation MAY interleave steps 2 and 3, returning **revoked** as soon as
any filter yields it without opening or querying the remaining covering
filters. No other outcome justifies early termination: after a filter yields
**not revoked**, **not enrolled**, or **not covered**, the remaining covering
filters MUST still be queried, since any of them may yet yield **revoked**.

If all covering filters return **not covered**, this indicates an issue with the
index and implementations SHOULD return an error instead of a revocation
result.

## Security considerations

This specification describes an offline revocation-checking mechanism whose
correctness depends on the integrity and freshness of the cache directory, and
on the caller having performed the checks it takes as prerequisites.

**Prior path validation.** The check procedure takes an end-entity certificate
and its issuing certificate as inputs and answers a single question: has that
end-entity certificate been revoked? It does not verify the end-entity
certificate's signature against the issuer's public key, does not construct or
validate a chain from the end-entity certificate to a trust anchor, and does not
enforce subject identity, validity periods, name constraints, key usage, or any
other constraint from [RFC 5280][]. Callers MUST perform [RFC 5280][] path
validation independently. A revocation result about a certificate that has not
also been validated in this manner is meaningless and MUST NOT be used to accept
a connection.

**SCT trust is external.** The `(LogID, timestamp)` pairs supplied by SCTs are
used here purely as index keys for selecting covering filters. Beyond the
signature validation required for detached SCTs (see
[Inputs](#inputs)), this specification does not enforce a CT-log-trust policy
(e.g. minimum number of SCTs, SCT diversity) and does not require that the
logs named by the SCTs be logs the caller trusts. Callers with specific
requirements on SCTs MUST enforce those requirements separately. Covering
filters that are selected based on malicious or malformed SCTs may give
inaccurate results.

**Cache authenticity.** Nothing in the on-disk format signs or otherwise
authenticates the filter files or `index.bin`. An implementation MUST
obtain the cache contents through an authenticated channel and MUST verify
its integrity before use. The mechanism for doing so is out of scope.

**Freshness.** A filter reflects the set of revocations known at the time it
was built. A recently issued and recently revoked certificate may not yet be
represented in any cached filter, and the check procedure will return
**not covered** or **not revoked** for such a certificate. Callers that need
a hard freshness guarantee MUST enforce it externally and nothing in this
document specifies how an implementation should notice that its cache is stale,
or refresh the data.

**Correctness depends on log operation.** A filter's coverage assertions
assume the covered CT logs honor their maximum merge delay (MMD). The
revocation status of a certificate that is not visible at a log's read
endpoint within one MMD of its SCT timestamp may not be encoded in a filter
that nonetheless claims to cover that `(LogID, timestamp)` pair, and querying
such a filter can produce a false **revoked** or false **not revoked**
result. Similarly, an SCT issued after a certificate was revoked may select
only filters that do not encode the certificate's revoked status. A client
relying exclusively on post-revocation SCTs can receive **not revoked** for a
revoked certificate.

**"Not covered" and "not enrolled" semantics.** Both outcomes assert that this
mechanism has no evidence about the certificate. In particular neither asserts
that the certificate is valid and unrevoked. **Not enrolled** additionally
indicates that the certificate's issuer was not part of the revocation data even
though the certificate's timestamps were covered, for example because the issuer
does not chain to a root in the root program from which the data is derived.
Callers MUST decide the meaning of these outcomes in their trust model
(fail-open, fail-closed, or delegate to another revocation mechanism), and MAY
treat "not covered" and "not enrolled" identically. Similar policy consideration
is required for certificates that are not presented with any SCTs and thus will
always present a **not covered** result for revocation queries.

**Malformed inputs.** Filter files and `index.bin` are parsed from untrusted
bytes if the cache authenticity check is imperfect. Implementations MUST
validate all length prefixes, offsets, and index values against the bounds
implied by the file size and the values already read, and MUST NOT allocate
memory proportional to length prefixes without first bounding those lengths
by the remaining file size. The wire format contains multiple opportunities
for pathological input (e.g. nested variable-length fields, `filter_idx` values
into the filename table, arbitrary `offset` values in the log directory) and
each MUST be checked for safe operation.

**Query key collisions.** The query key is `SHA-256(issuer_spki_hash ||
serial)`. Collisions in SHA-256 within a single issuer's serial-number space
would produce incorrect results, but constructing such a collision is
computationally infeasible under current assumptions without compromising the
issuing CA. This revocation mechanism targets the Web PKI where issuance of
duplicated serials by a single issuer is a misissuance event.

## Acknowledgements

The clubcard construction and its query algorithm were specified and developed
by John M. Schanck to support [Mozilla Firefox][] for [CRLite][] and published
in "Clubcards for the WebPKI: Smaller Certificate Revocation Tests in Theory and
Practice", 2025 IEEE Symposium on Security and Privacy (SP), pp. 652–663,
[doi:10.1109/SP61157.2025.00128][Schanck 2025].

The index format, and V4 Clubcard CRLite serialization format were developed by
Dirkjan Ochtman and Joe Birr-Pixton in collaboration with John M. Schanck in
order to support the [rustls/upki][upki] project. The specification text in this
document was initially drafted by Daniel McCarney.

[Mozilla Firefox]: https://www.firefox.com/
