# .well-known/ssh-known-hosts

[c2sp.org/well-known-ssh-hosts](https://c2sp.org/well-known-ssh-hosts)

This document describes the `.well-known/ssh-known-hosts`, which can
be used to share a verified SSH host key for a domain over HTTPS.

## Introduction

SSH clients must verify the host key of the server matches what they
expect. Today this is a manual process that requires users to discover
the host key out of band and ensure it matches on first retrieval.
(After the first connection, it is cached locally by clients in the
~/.ssh/known_hosts file.)

With the `.well-known/ssh-known-hosts` file, a service can advertise
its host key over HTTPS and can be discovered automatically.

For example, a service such as GitHub can serve
https://github.com/.well-known/ssh-known-hosts with the contents
matching the standard sshd known_hosts file:

```
github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl
```

As the TLS connection to the URL can be mechanically verified to come
from github.com, the host key can be automatically trusted for SSH
connections to github.com without manual user intervention.

## Format

The file format is a subset of the format described in the sshd(8)
manual in the
[SSH_KNOWN_HOSTS FILE FORMAT](https://man.openbsd.org/sshd.8#SSH_KNOWN_HOSTS_FILE_FORMAT)
section.
Each line represents a host key (or a @cert-authority) for a host.

The major restrictions on that format are to ensure all the hosts
match the domain the .well-known file is being served from.
They include:

* Hashed hostnames are rejected
* Wildcards are ignored in the segment to the left of TLD and CCTLD's
  (e.g. *.com is ignored, and *.co.uk is ignored, but *.example.com is allowed)
* Hostnames other than the domain must be ignored
* IP addresses are rejected unless they exactly match a TLS certificate subject
* The base64 must be valid
* The decoded key must parse correctly

Many of the less-used features are supported: @cert-authority,
@revoked (if the domain matches), non-standard ports.

## Conflicts with SSHFP

Users should be notified of conflicts with SSHFP records if both are valid and
DNS is validated via DNSSEC.
