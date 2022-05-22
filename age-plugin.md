{%hackmd theme-dark %}

# Plugin system for age

## Introduction

The age file encryption format follows the "one well-oiled joint" design
philosophy. The mechanism for extensibility (within a particular format version)
is the recipient stanzas within the age header: file keys can be wrapped in any
number of ways, and age clients are required to ignore stanzas that they do not
understand. The core APIs that exercise this mechanism are:

- A recipient that wraps a file key and returns a stanza.
- An identity that unwraps a stanza and returns a file key.

Custom age clients can bundle support for the exact recipient or identity types
required for a particular environment. However, a general plugin system will
enable an ecosystem of common third-party recipient types to grow.

The plugin system specified in this document provides a mechanism for exposing
the core APIs across process boundaries. It has two main components:

- A map from recipients and identities to plugin binaries.
- State machines for wrapping and unwrapping file keys.

With this composable design, developers can implement a recipient or identity
that they would use directly with an age library, and then also deploy it as a
plugin binary.

## Conventions used in this document

The Base64 encoding used throughout is the standard Base 64 encoding specified
in [RFC 4648][], Section 4, without padding characters. Encoders MUST generate
canonical Base64 according to RFC 4648, Section 3.5, and decoders MUST reject
non-canonical encodings.

## Mapping recipients and identities to plugin binaries

age plugins are identified by an arbitrary case-insensitive string `NAME`. This
string is used in three places:

- Plugin-compatible recipients are encoded using Bech32 with the HRP `age1name`
  (lowercase).
- Plugin-compatible identities are encoded using Bech32 with the HRP
  `AGE-PLUGIN-NAME-` (uppercase).
- Plugin binaries (to be started by age clients) are named `age-plugin-name`.

Users interact with age clients by providing either recipients for file
encryption, or identities for file decryption. When a plugin recipient or
identity is provided, the age client searches the `PATH` for a binary with the
corresponding plugin name.

Recipient stanza types are not required to be correlated to specific plugin
names. When decrypting, age clients will pass all recipient stanzas to every
connected plugin. Plugins MUST ignore stanzas that they do not know about.

A plugin binary may handle multiple recipient or identity types by being present
in the `PATH` under multiple names. This can be implemented with symlinks or
aliases to the canonical binary.

Multiple plugin binaries can support the same recipient and identity types; the
first binary found in the `PATH` will be used by age clients. Some Unix OSs
support "alternatives", which plugin binaries should leverage if they provide
support for a common recipient or identity type.

Note that the identity specified by a user doesn't need to point to a specific
decryption key, or indeed contain any key material at all. It only needs to
contain sufficient information for the plugin to locate the necessary key
material.

### Standard age keys

A plugin MAY support decrypting files encrypted to native age recipients, by
including support for the `x25519` recipient stanza. Such plugins will pick
their own name, and users will use identity files containing identities that
specify that plugin name.

### Agents for age identities

One use-case for plugins is for implementing agents for age identities. The
expected design is a short-lifetime plugin binary `age-plugin-NAME`, which
implements the plugin protocol, and in turn connects to (or starts, if not
already running) a long-lifetime agent daemon. Specification of agents is
out of scope for this document.

## State machines

A plugin operates using one of several state machines. The age client chooses
which state machine to use when it starts the plugin, by passing an argument
flag `--age-plugin=STATE_MACHINE` which specifies the type and version of the
state machine. This document defines the following state machines:

- `recipient-v1` - for wrapping file keys during file encryption.
- `identity-v1` - for unwrapping file keys during file decryption.

Plugins MUST NOT make any assumptions about the working directory that they are
run inside.

A plugin MUST refuse to start if it does not know about the requested state
machine; in this situation, or if a plugin otherwise terminates early with an
error, the age client:

- MUST propagate the failure to the user if it occurs during file encryption
  (which would mean that the file could not be encrypted to one of the requested
  recipients). This may include displaying the contents of the plugin's standard
  error to the user.
- MAY ignore the failure if it occurs during file decryption (and try another
  identity or plugin).

It is expected that the same plugin binary will be used (potentially with other
argument flags) for administrative tasks like generating keys.

### IPC protocol

The IPC protocol for v1 state machines is built around an age stanza, using the
same text format as the age format v1 header:

- The tag field is used for command and response types.
- The arguments array is used for command-specific metadata.
- The body contains data associated with the command, if any.

In the rest of this document, stanzas will be specified with the following
notations (optional fields indicated with `[brackets]`):

- `(COMMAND[, METADATA][; DATA])`
- `(COMMAND, [METADATA] STANZA...)` - `STANZA` is a complete stanza.
- `(COMMAND)` - a command with no metadata or data.

Stanzas are serialized exactly as in age headers, using the explicit encoding
of stanza bodies. For example, if three commands are sent, and the second
command has no associated data:
```
-> command-1 metadata
Base64(data)
-> command-2 more metadata

-> command-3
Base64(lots of)
Base64(data)
```

Note that because the first line of an age stanza consists of SP-separated
arbitary strings, the tag field is always a valid argument. We leverage this in
order to send stanzas directly between the age client and plugin, by prepending
the stanza's first line with an appropriate command and/or additional metadata.

Communication between the client and plugin happens over the plugin's standard
input and standard output. This inherently makes the IPC uni-directionally
synchronous: stanzas have a well-defined order within a specific direction (e.g.
client to plugin). The IPC protocol does not track or enforce a bi-directional
ordering of stanzas; this is handled within the state machine.

### Phases

The state machines for wrapping and unwrapping are composed of several phases.
Each phase is separated by an explicit `done` command with no metadata or data.
A phase is controlled by either the age client or the plugin; the controller
initiates all communication during the phase. There are two kinds of phases:

- Uni-directional: the controller sends a series of commands, terminated by the
  `done` command. The other party is expected to store the effects of these
  commands for use in a subsequent phase.
- Bi-directional: the controller sends a command, and synchronously waits for a
  response to that command. This is repeated until the controller terminates the
  phase with the `done` command.

State machine versions enable future specification of backwards-incompatible
state machines (that would likely be associated with new age format versions).
However, backwards-compatible changes may be made to existing state machines.
To ensure backwards-compatibility, other partys MUST handle receiving
unsupported commands. The other party's behaviour depends on the type of phase:

- Uni-directional: the other party MUST ignore all commands it does not know
  about.
- Bi-directional: the other party MUST respond with an `unsupported` command
  with no metadata or data.

### Grease

To ensure that the above joint does not rust (and similarly to the age format
header), each phase supports the addition of "grease": age stanzas with random
commands (that MUST NOT collide with existing defined commands for that phase),
and random (potentially-empty) metadata and data.

During a phase, the controller MAY send one or more grease stanzas at any point
where they might otherwise send a command. Note that grease cannot replace the
`done` command, but a phase may otherwise have multiple commands sent even if it
is defined as a single-command phase.

### TODO: Errors

... and how to handle unknown error types in a phase.

## Wrapping with `recipient-v1`

This state machine wraps a single file key (for a single age-encrypted file) to
multiple recipients and/or identities. It enables amortization of identity-specific
costs (such as requesting a PIN or passphrase from the user) across multiple file
encryptions.

### Phase 1 [client, uni-directional]

Three commands are defined for this phase:

- `(add-recipient, RECIPIENT)` - specifies a recipient that the client wants to
  wrap all the file keys to.
  - `RECIPIENT` is the Bech32 encoding of a recipient.
- `(add-identity, IDENTITY)` - specifies an identity that the client wants to
  wrap all the file keys to.
  - `IDENTITY` is the Bech32 encoding of an identity.
- `(wrap-file-key; FILE_KEY)` - a file key to be wrapped.

The plugin indexes recipients, identities, and file keys in the order received
(starting from 0). The two may be interleaved by the client, with no semantic
implications. The plugin caches each recipient, identity, and file key internally.

Example phase diagram:
```
-> add-recipient foo

-> add-identity bar

-> wrap-file-key
Base64(FILE_KEY)
-> add-recipient baz

-> wrap-file-key
Base64(FILE_KEY)
-> done

```

### Phase 2 [plugin, bi-directional]

The following commands and responses are defined for this phase:

- `(msg; MESSAGE)` - a message that should be displayed to the user, for
  example to prompt them to interact with a hardware key.
  - Response is `(ok)` (if the message can be displayed) or `(fail)` (if, for
    example, there is no UI for displaying messages).
  - The response MAY be sent by the client before the message has been displayed
    to the user.
- `(confirm, Base64(YES_STRING) [Base64(NO_STRING)]; MESSAGE)` - a request for
  confirmation that should be displayed to the user, for example to ask them to
  either plug in a hardware key or skip it.
  - `MESSAGE` is the request or call-to-action to be displayed to the user.
  - `YES_STRING` and (optionally) `NO_STRING` are strings that will be displayed
    on buttons or next to selection options in the user's UI.
  - Response is one of the following:
    - `(ok, yes)` if the user selected the option marked with `YES_STRING`.
    - `(ok, no)` if the user selected the option marked with `NO_STRING`.
    - `(fail)` if the confirmation request could not be given to the user (for
      example, if there is no UI for displaying messages).
- `(request-public; MESSAGE)` - the plugin requires some public string from the
  user in order to progress.
  - Response is `(ok; REQUESTED_PUBLIC)` or `(fail)`.
- `(request-secret; MESSAGE)` - the plugin requires a secret or PIN from the
  user in order to progress.
  - Response is `(ok; REQUESTED_SECRET)` or `(fail)`.
- `(recipient-stanza, FILE_INDEX STANZA...)` - a stanza containing a correctly-wrapped
  file key to one of the recipients.
  - The stanzas do not need to be sent in any particular order; clients will not
    be mapping the stanzas to specific recipients, and will cache stanzas for
    separate files until the state machine completes.
  - Response is `(ok)`.
- An `error` command with three variants:
  - `(error, recipient RECIPIENT_INDEX; MESSAGE)` - a specific recipient is the
    cause of an error.
    - Response is `(ok)`.
  - `(error, identity IDENTITY_INDEX; MESSAGE)` - a specific identity is the
    cause of an error.
    - Response is `(ok)`.
  - `(error, internal; MESSAGE)` - a general error occurred during wrapping.
    - Response is `(ok)`.

Having assembled the full set of recipients and identities that the client wishes
to wrap to, the plugin determines whether it can successfully wrap to all
recipients and identities. The plugin MUST generate an error if one or more
recipients or identities cannot be wrapped to.

The plugin then proceeds to wrap the given file keys to the recipients and
identities. While doing so, the plugin may send commands to request additional
help from the client / user.

The plugin is the controller of this phase; clients should not close the
connection if, for example, a user fails to respond in the way the plugin wants
for a particular request. Instead, the client returns `(fail)` to indicate this;
the plugin then decides whether this response is fatal.

If any errors occur, the plugin MUST NOT send any stanzas to the client.

Once all file keys have been successfully wrapped to all recipients and identities,
the plugin sends the resulting stanzas to the client. The plugin MUST NOT return
more stanzas per file than the number of recipients and identities.

Example phase diagram:
```
-> request-secret ...
  < ok\nSECRET
-> request-secret ...
  < fail
-> msg  ...
  < ok
-> recipient-stanza 0 ...
  < ok
-> recipient-stanza 1 ...
  < ok
-> recipient-stanza 0 ...
  < ok
-> recipient-stanza 1 ...
  < ok
-> done
```

## Unwrapping with `identity-v1`

This state machine unwraps multiple file keys from multiple age-encrypted files.
It enables amortization of identity-specific costs (such as requesting a PIN or
passphrase from the user) across multiple file decryptions.

### Phase 1 [client, uni-directional]

Two commands are defined for this phase:

- `(add-identity, IDENTITY)` - specifies an identity to be used by the plugin
  for trial-unwrapping.
  - `IDENTITY` is the Bech32 encoding of an identity.
- `(recipient-stanza, FILE_INDEX STANZA...)` - conveys a stanza from an age format
  v1 header.
  - File indices are numeric, ordered, and monotonically increasing. Duplicate
    file indices indicate stanzas that are from the same file header, and wrap
    the same file key.

The plugin indexes identities and stanzas in the order received (starting from
0). The two may be interleaved by the client, but the `recipient-stanza` file
indices must remain ordered and monotonically increasing.

Unknown stanza types MUST be ignored by the plugin.

Example phase diagram:
```
-> add-identity foo

-> recipient-stanza 0 ...
-> add-identity bar

-> recipient-stanza 0 ...
-> recipient-stanza 0 ...
-> recipient-stanza 1 ...
-> recipient-stanza 1 ...
-> add-identity baz

-> recipient-stanza 1 ...
-> recipient-stanza 2 ...
-> done

```

### Phase 2 [plugin, bi-directional]

The following commands and responses are defined for this phase:

- `(msg; MESSAGE)` - a message that should be displayed to the user, for
  example to prompt them to interact with a hardware key.
  - Response is `(ok)` (if the message can be displayed) or `(fail)` (if, for
    example, there is no UI for displaying messages).
  - The response MAY be sent by the client before the message has been displayed
    to the user.
- `(confirm, Base64(YES_STRING) [Base64(NO_STRING)]; MESSAGE)` - a request for
  confirmation that should be displayed to the user, for example to ask them to
  either plug in a hardware key or skip it.
  - `MESSAGE` is the request or call-to-action to be displayed to the user.
  - `YES_STRING` and (optionally) `NO_STRING` are strings that will be displayed
    on buttons or next to selection options in the user's UI.
  - Response is one of the following:
    - `(ok, yes)` if the user selected the option marked with `YES_STRING`.
    - `(ok, no)` if the user selected the option marked with `NO_STRING`.
    - `(fail)` if the confirmation request could not be given to the user (for
      example, if there is no UI for displaying messages).
- `(request-public; MESSAGE)` - the plugin requires some public string from the
  user in order to progress.
  - Response is `(ok; REQUESTED_PUBLIC)` or `(fail)`.
- `(request-secret; MESSAGE)` - the plugin requires a secret or PIN from the
  user in order to progress.
  - Response is `(ok; REQUESTED_SECRET)` or `(fail)`.
- `(file-key, FILE_INDEX; FILE_KEY)` - an unwrapped file key.
  - Response is `(ok)`.
- An `error` command with three variants:
  - `(error, identity IDENTITY_INDEX; MESSAGE)` - an error occured while using
    this identity.
    - Response is `(ok)`.
  - `(error, stanza FILE_INDEX STANZA_INDEX; MESSAGE)` - an error occured while
    using a specific stanza. This MUST NOT be used for unknown stanzas, only for
    stanzas with an expected tag but that are otherwise invalid (indicating an
    invalid age header).
    - Response is `(ok)`.
  - `(error, internal; MESSAGE)` - a general error occurred during unwrapping.
    - Response is `(ok)`.

Having assembled the full list of identities to use, and supported stanzas to
trial-unwrap, the plugin enforces structural validity on both:
- If there are unknown or invalid identity types, the plugin MUST return errors
  and MUST NOT attempt to unwrap any file keys with otherwise-valid identities.
- If any known stanza is structurally invalid, the plugin MUST return an error
  for that stanza, and MUST NOT unwrap any stanzas with the same `FILE_INDEX`.
  The plugin MAY continue to unwrap stanzas from other files.

The plugin then chooses internally an order of identities to try, and sends
commands to request additional help from the client / user, or store unwrapped
file keys.

The plugin is the controller of this phase; clients should not close the
connection if, for example, a user fails to respond in the way the plugin wants
for a particular request. Instead, the client returns `(fail)` to indicate this;
the plugin is expected to try another recipient stanza or identity.

When the plugin is able to determine whether a given file key can be unwrapped
or not, it takes one of three actions:
- If a stanza cannot be unwrapped that detectably should be unwrappable (e.g.
  the stanza specifically identifies the recipient), the plugin sends
  `error stanza`.
  - TODO: Should this be a hard error (preventing that file from being unwrapped)?
    Probably yes (we already assume we don't get 32-bit collisions for SSH tags).
- If any recipient stanza with a given `FILE_INDEX` can be unwrapped, it sends
  `file-key`.
- If all known and valid stanzas for a given file cannot be unwrapped, and none
  are expected to be unwrappable, the plugin does not send anything. That is,
  file keys that cannot be unwrapped are implicit.

These may be interleaved with other requests, and the client must cache the
unwrapped file keys until this phase is complete. The plugin sends no more than
one file key per file index in the original set of stanzas.

- TODO: Should IPC errors (e.g. invalid command structure or argument types) be
  separated from state machine errors (e.g. invalid identities)?
  - Probably not; it should be possible to run the IPC protocol over e.g. TCP.
- TODO: What about identities that are not unknown or invalid, but for which we
  get an error while trying to use them? (e.g. YubiKey missing, invalid PIN,
  cloud KMS rejection)

Example phase diagram:
```
-> request-secret ...
  < ok\nSECRET
-> request-secret ...
  < ok\nSECRET
-> file-key FILE_INDEX ...
  < ok
-> file-key FILE_INDEX ...
  < ok
-> request-secret ...
  < fail
-> msg  ...
  < ok
-> error ...
  < ok
-> file-key FILE_INDEX ...
  < ok
-> file-key FILE_INDEX ...
  < ok
-> msg  ...
  < fail
-> error ...
  < ok
-> file-key FILE_INDEX ...
  < ok
-> done
```

## Example interactions

- `A`: age client
- `P`: plugin

### Key wrapping

```text
A --> P | -> add-recipient RECIPIENT_1
        |
A --> P | -> add-recipient RECIPIENT_2
        |
A --> P | -> wrap-file-key
        | Base64(FILE_KEY)
A --> P | -> done
        |
A <-- P | -> recipient-stanza 0 some-tag CJM36AHmTbdHSuOQL+NESqyVQE75f2e610iRdLPEN20
        | C3ZAeY64NXS4QFrksLm3EGz+uPRyI0eQsWw7LWbbYig
A <-- P | -> recipient-stanza 0 another-tag 42 ytazqsbmUnPwVWMVx0c1X9iUtGdY4yAB08UQTY2hNCI
        | N3pgrXkbIn/RrVt0T0G3sQr1wGWuclqKxTSWHSqGdkc
A <-- P | -> done
        |
```

### Key unwrapping

```text
A --> P | -> add-identity YUBIKEY_ID_PIN_REQUIRED
        |
A --> P | -> add-identity YUBIKEY_ID_NO_PIN
        |
A --> P | -> recipient-stanza 0 yubikey BjH7FA RO+wV4kbbl4NtSmp56lQcfRdRp3dEFpdQmWkaoiw6lY
        | 51eEu5Oo2JYAG7OU4oamH03FDRP18/GnzeCrY7Z+sa8
A --> P | -> recipient-stanza 1 yubikey mhir0Q ZV/AhotwSGqaPCU43cepl4WYUouAa17a3xpu4G2yi5k
        | fgMiVLJHMlg9fW7CVG/hPS5EAU4Zeg19LyCP7SoH5nA
A --> P | -> done
        |
A <-- P | -> msg
        | Base64("Please insert YubiKey with serial 65227134")
A --> P | -> ok
        |
A <-- P | -> file-key 0
        | Base64(FILE_KEY)
A --> P | -> ok
        |
A <-- P | -> request-secret
        | Base64("Please enter PIN for YubiKey with serial 65227134")
A --> P | -> ok
        | Base64(123456)
A <-- P | -> file-key 1
        | Base64(FILE_KEY)
A --> P | -> ok
        |
A <-- P | -> done
        |
```

## Rationale

The two driving goals behind the design are:

- No configuration.
- Simplest user experience possible.

In order to have no configuration, age clients need to be able to detect, for
example, which plugins support which recipient types. The simplest way to do
this is to have a 1:1 relationship between plugins and recipient types.

### Considered Alternatives

- An age plugin could be queried for supported recipient types. This was
  discounted because it requires starting every installed plugin when only a
  subset of them might actually be able to encrypt or decrypt a given message.

- An age plugin could, at install time, store a file containing the recipient
  types that it supports. This was discounted because it requires significantly
  more complex configuration support; instead of only needing one per-user
  folder, we would also need to handle system configuration folders across
  various platforms, as well as be safe across OS upgrades.

[RFC 4648]: https://www.rfc-editor.org/rfc/rfc4648.html
