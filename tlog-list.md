---
description: Text format for lists of transparency logs and their witnessing parameters
---

> [!WARNING]
> This is the editor's copy of this specification.
> For a stable rendered reference, use [c2sp.org/tlog-list](https://c2sp.org/tlog-list).

# Transparency Log Lists

This document describes a line-terminated log-list format.

Lines are separated by newline (0x0A) characters.
Lines have all leading and trailing space (0x20) and tab (0x09) characters removed before processing.
Blank lines are ignored.
Lines starting with `#` denote comments and are also ignored.

## Example

    #
    # List:      10qps-100klogs
    # Revision:  123
    # Generated: YYYY-MM-DD HH:MM:SS UTC
    # Other undefined debug information.
    #
    logs/v0

    # 1st list item -- foo's log
    vkey tlog.foo.org+aaaaaa+AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
    qpd 86400
    contact https://tlog.foo.org/contact

    # 2nd list item -- bar's log
    vkey bar.org/tlog+bbbbbbbb+BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
    origin something-not-equal-to-vkey-keyname
    	qpd 24
    	contact sysadmin (at) bar.org

## Header

The list starts with a single line declaring the list format.

    logs/v0

Zero or more logs follow after the `logs/v0` line.

## List of logs

A log is identified by its origin, and defined by a sequence of key-value lines.
For each log, the order of key-value lines is fixed and MUST match the order defined below.
Lines that are optional are denoted by square brackets.

    vkey VKEY
    [origin ORIGIN]
    qpd QPD
    contact CONTACT

`VKEY` is the log's verification key in vkey format, see <https://c2sp.org/signed-note#verifier-keys>.
Each log can have only one vkey.

`ORIGIN` is the log's origin line, see <https://C2SP.org/tlog-checkpoint#note-text>.
If omitted, the log's origin line defaults to the vkey's key name.
Newly deployed logs SHOULD omit this line.
Two logs MUST NOT share the same origin.

`QPD` is the number of add-checkpoint requests the log may do per day.
It MUST be a number in the range [1, 2^31) encoded as an ASCII decimal consisting of characters in the range `0`-`9` only, with no leading zeroes.

`CONTACT` is an arbitrary string useful for humans to reach the log operator.

This key-value sequence repeats for each defined log.
