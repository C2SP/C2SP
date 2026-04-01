# Transparency log trust policy

## Introduction

This document specifies a transparency log policy file format. The
policy can be used and enforced by several of the parties in a
transparency log system, but the most important use is for offline
verification of a proof of logging. In addition, a policy file may be
used also used by monitors, submitters, and log servers.

The policy only specifies how to validate a checkpoint. Information
needed for additional steps required by an offline verifier (e.g.,
trusted public keys for verifying signatures within a logged entry of
interest) is out of scope.

## What is a "policy"?

A transparency log policy includes three pieces of information.

* A set of known logs.

* A set of known witnesses.

* The quorum: the rule that determines whether or not a subset of
  witnesses that have cosigned a checkpoint is strong enough to
  consider the checkpoint to be valid.

Only the quorum is mandatory. An application where the appropriate
log(s) are known from other context may accept a policy with an empty
set of logs. A policy without witness cosigning can be defined using a
`quorum none` line, and in this case, the set of witnesses may be
empty.

The policy says that a checkpoint is considered valid if it is signed
by any one of the listed logs, and it is cosigned by witnesses
according to the defined quorum rule.

Both logs and witnesses are identified primarily by their public keys.
Each log or witness may also have an associated URL; this is required
for operations interacting with the log or witness, but no URLs are
required if the policy is used only for offline verification.

Witnesses (and groups, described below) are named. These names are
used only for defining the quorum and group membership; they have no
meaning outside of the policy file itself. Witnesses and groups share
a single namespace. The special name `none` is predefined; it can
be used when defining the quorum, but it is invalid as a group member.

We will look at an example policy, before specifying the contents of
the policy file in detail.

## Example policy

This is an example of a policy with a quorum defined using two levels of
groups. Actual keys are elided, for brevity, and the optional URLs are
omitted:
```
log <vkey>

witness X1 <vkey>
witness X2 <vkey>
witness X3 <vkey>
group X-witnesses 2 X1 X2 X3

witness Y1 <vkey>
witness Y2 <vkey>
witness Y3 <vkey>
group Y-witnesses any Y1 Y2 Y3

group X-and-Y all X-witnesses Y-witnesses
quorum X-and-Y
```
This policy file lists a single log and six witnesses. The witnesses
are divided into two groups, e.g., because the `X-witnesses` are
operated by one organization, and the
`Y-witnesses` are operated by a separate organization.

The number "2" in the definition of the `X-witnesses` is a threshold.
It means that if at least two out of these three witnesses have
cosigned (or "witnessed") a checkpoint, then the group is considered to
have witnessed that same checkpoint. The keywords "all" and "any" can be
used instead of a numeric threshold.

The quorum definition in this example means that when verifying a
checkpoint, it is required that there are valid cosignatures
from at least two of the `X-witnesses`, and from at least one of the
`Y-witnesses`, and this rule is represented by the group `X-and-Y`.

## Policy file syntax and structure

### Structure

The policy file is line based, where each line is terminated by ASCII
newline, and the items on each line are separated by "whitespace",
which in this specification means sequences of ASCII space and tab
characters *only*. Leading and trailing whitespace is allowed. Comment
lines are written with "#" at the start of the line (possibly preceded
by whitespace).

Lines defining witnesses and logs can appear in any order; the order
does not imply any preference or priority. A line defining a group can
only reference names of groups and witnesses defined on preceding
lines. Similarly, the quorum line must specify a witness or group
defined earlier.

### Public key representation

Public keys are written in [vkey][] format. (The `sigsum-key` command
can be used to convert public keys between raw hex, OpenSSH, and
[vkey][] formats). Log keys must use signature type `0x01` (Ed25519),
and witness keys must use signature type `0x04` (Timestamped Ed25519
witness cosignatures). Two vkeys are considered *duplicate* if they
wrap the same underlying Ed25519 public key, even if they differ by
key name and key id.

[vkey]: https://github.com/C2SP/C2SP/blob/main/signed-note.md#verifier-keys

### Defining a log

A log is defined by a line
```
log <vkey> [<url>]
```
When the policy is used for verifying a proof, all of the
listed logs are accepted. 

The log's vkey includes a "key name". This name MUST correspond to the
log's origin line, representing the identity of the log.

The meaning of the URL is application specific, but when present, it
is intended to provide a way to interact with the log, for monitoring,
or to submit entries. (E.g., the `sigsum-submit` tool requires that
the URL is the log's "base URL" as defined by the Sigsum log api. The
tool then tries provided URLs in randomized order, until submission to
one of the logs succeeds).

Duplicate logs, i.e., multiple log lines with the same public key, are
not allowed.

### Defining a witness

A witness is defined by a line
```
witness <name> <vkey> [<url>]
```
The name is used to refer to this witness when defining the quorum, or
when defining witness groups.

Since only logs and possibly monitors interact directly with
witnesses, most policy files will not need any witness URLs. The
meaning of the URL is application specific, but if a URL is provided,
it is recommended that it is the witness' "submission prefix" URL, as
defined by the [witness protocol][].

Duplicate witnesses, i.e., multiple witness lines with the same public
key, are not allowed.

[witness protocol]: ./tlog-witness.md

### Defining the quorum

The quorum is defined by a line
```
quorum <name>
```
In the simplest case, the name refers to a witness, and it means that
a cosignature from that witness is required for a checkpoint to be
considered valid.

To not require any cosignatures at all, one can use the predefined name
`none` as follows:
```
quorum none
```
To define more interesting quorums, the name can also refer to a witness
group, the next topic. In either case, the name must be properly
defined on a line preceding the quorum definition.

A policy file must include exactly one quorum line.

### Defining a witness group

Defining a witness group is required for defining a quorum that is not
a single witness. A group is defined by a line of one of these forms:
```
group <name> all <name>...
group <name> any <name>...
group <name> <k> <name>...
```

Each of these defines a group, where the group is considered to
witness a checkpoint if and only if at least k of its n members have
witnessed that checkpoint, each group member being either a witness or
another group. In this terminology, for a single witness, "witnessing"
is the same as cosigning.

At least one member must be listed (i.e., n >= 1). The `any` variant
is a shorthand for k = 1, and the `all` variant is a shorthand for k =
n. If k is given numerically, it must be written in decimal, and it is
required that 1 <= k <= n.

Like for the quorum definition, a group definition can only refer to
names defined on preceding lines. (This also rules out circular group
definitions).

Each defined name can be listed as a group member at most once. This
ensures that each witness can contribute to a group, or to the quorum
in particular, in only one way.

### Character set

The policy file is treated as a file of octets, where octets with the
most significant bit clear are interpreted as ASCII characters. The
only allowed control characters are tab and newline, which means that
the allowed octet values are 0x09 (tab), 0x0A (newline), 0x20-0x7E,
and 0x80-0xFF.

Non-ASCII octets may appear in names, URLs and comments. Using UTF-8
for any non-ASCII text is strongly recommended, but with respect to
the policy file syntax and semantics, all octets with the high bit set
are opaque. In particular, names must be handled as opaque octet
strings, e.g., the name 0x4B (ASCII "K") is different from the name
0xE2 0x84 0xAA (a Kelvin sign encoded using UTF-8).

The motivations for allowing non-ASCII, but handling it as opaque
data, are to:

* Ensure that processing the policy file does not require unicode
  awareness and corresponding tables, and that the meaning of the
  policy does not depend on the unicode version used.

* Allow using any [signed note key name][] as a witness name, allow
  international domain names in URLs (without resorting to punycode),
  and allow free use of non-ASCII comments.

[signed note key name]: https://github.com/C2SP/C2SP/blob/main/signed-note.md#format

### Implementation limits

An implementation of transparency log policy may impose limits on
policy complexity. It is strongly recommended that an implementation
supports at least up to 32 logs, 32 witnesses, and 32 groups.
