# Reference Implementation for jq255e and jq255s

This directory contains the reference implementation for the jq255e and
jq255s groups, as described in [the specification](../jq255.md). It is
written in Python (3.4+) and meant for testing purposes (e.g.
demonstrating the use of the formulas, or generating test vectors). It
is *not* constant-time (i.e. it may leak information about secret
values) and, as such, should not be used in production deployments.
