# PHC string format

## Example

Given the following inputs:

* Password: `hunter2`
* Salt: ```\x81\x98\x95\xFC\xCD`=\xCD\xB6\x12P\a\xFC\x98u\x1F```
* Secret: `pepper`
* Variant: `argon2id`
* Version: `19`
* Time cost: `2`
* Memory cost: `65536`
* Parallelism cost: `1`

Argon2 will generate the following digest:

`$argon2id$v=19$m=65536,t=2,p=1$gZiV/M1gPc22ElAH/Jh1Hw$CWOrkoo7oJBQ/iyh7uJ0LO2aLEfrHwTWllSAxT0zRno`

## Specification

This document specifies string encodings for the output of a password
hashing function. Three kinds of strings are defined:

  - Parameter string: identifies the function and contains values for
    its parameters.
  - Salt string: a parameter string that also specifies the salt value.
  - Hash string: a salt string that also specifies the hash output.

The specification calls for deterministic encoding: for a given
function, set of parameters, salt value and output, producers MUST
output the exact unique sequence of characters prescribed in this
documentation. This allows testing with regards to explicit test
vectors, and promotes interoperability by discouraging local variants.
Consumers may accept other encodings, but are also allowed to reject any
string that differs from the format herein described.


We define the following format:

       $<id>[$v=<version>][$<param>=<value>(,<param>=<value>)*][$<salt>[$<hash>]]

where:

 - `<id>` is the symbolic name for the function
 - `<version>` is the algorithm version
 - `<param>` is a parameter name
 - `<value>` is a parameter value
 - `<salt>` is an encoding of the salt
 - `<hash>` is an encoding of the hash output

The string is then the concatenation, in that order, of:

 - a `$` sign;
 - the function symbolic name;
 - optionally, a `$` sign followed by the algorithm version with a `v=version` format;
 - optionally, a `$` sign followed by one or several parameters, each
   with a `name=value` format; the parameters are separated by commas;
 - optionally, a `$` sign followed by the (encoded) salt value;
 - optionally, a `$` sign followed by the (encoded) hash output (the
   hash output may be present only if the salt is present).

The function symbolic name is a sequence of characters in: `[a-z0-9-]`
(lowercase letters, digits, and the minus sign). No other character is
allowed. Each function defines its own identifier (or identifiers in
case of a function family); identifiers should be explicit (human
readable, not a single digit), with a length of about 5 to 10
characters. An identifier name MUST NOT exceed 32 characters in length.

The value for the version shall be a sequence of characters in: `[0-9]`.

Each parameter name shall be a sequence of characters in: `[a-z0-9-]`
(lowercase letters, digits, and the minus sign). No other character is
allowed. Parameter names SHOULD be readable for a human user. A
parameter name MUST NOT exceed 32 characters in length. A parameter
name MUST NOT be equal to the string `v` (to avoid confusion with the
version field).

The value for each parameter consists in characters in:
`[a-zA-Z0-9/+.-]` (lowercase letters, uppercase letters, digits, `/`,
`+`, `.` and `-`).  No other character is allowed. Interpretation of the
value depends on the parameter and the function. The function
specification MUST unambiguously define the set of valid parameter
values. The function specification MUST define a maximum length (in
characters) for each parameter. For numerical parameters, functions
SHOULD use plain decimal encoding (other encodings are possible as long
as they are clearly defined).

The function specification MUST define a clear, unambiguous,
deterministic encoding for each possible value of a parameter. Producers
of strings MUST follow that encoding. Consumers MAY accept alternate
encodings.

A version may be optional; if the version is optional, then the
function MUST define the default version to use.

A parameter may be optional; if a parameter is optional, then the
function MUST define the default value of the parameter. That default
value MUST NOT be subject to context-dependent alterations (e.g. a value
configurable in a system-wide setting is not an acceptable default).
When a parameter is optional, producers MUST omit the parameter if its
value is equal to the default value. The function MUST specify which
parameters are optional and which are not.

The function MUST specify the order in which parameters may appear.
Producers MUST NOT allow parameters to appear in any other order.

If the function expects no parameter at all, or all parameters are
optional and their value happens to match the default, then the complete
list, including its starting `$` sign, is omitted. Note that the `=`
sign may appear within the complete string only as part of a list of
parameters.

The salt consists in a sequence of characters in: `[a-zA-Z0-9/+.-]`
(lowercase letters, uppercase letters, digits, `/`, `+`, `.` and `-`).
The function specification MUST define the set of valid salt values and
a maximum length for this field. Functions that work over arbitrary
binary salts SHOULD define that field to be the B64 encoding for a
binary value whose length falls in a defined range or set of ranges.

The hash output, if present (in a "hash string"), MUST be the B64
encoding of the raw output of the hash function. The function
specification MUST define the minimum, maximum and default output
length.


### B64

The B64 encoding is the standard Base64 encoding (RFC 4648, section 4)
except that the padding `=` signs are omitted, and extra characters
(whitespace) are not allowed:

  - Input is split into successive groups of bytes. Each group, except
    possibly the last one, contains exactly three bytes.

  - For a group of bytes b0, b1 and b2, compute the following value:

           x = (b0 << 16) + (b1 << 8) + b2

    Then split `x` into four 6-bit values `y0`, `y1`, `y2` and `y3`
    such that:

           x = (y0 << 18) + (y1 << 12) + (y2 << 6) + y3

  - Each 6-bit value is encoded into a character in the `[A-Za-z0-9+/]`
  alphabet, in that order:
    * `A`..`Z` = 0 to 25
    * `a`..`z` = 26 to 51
    * `0`..`9` = 52 to 61
    * `+` = 62
    * `/` = 63

  - If the last group does not contain exactly three bytes, then:

    1. The group is completed with one or two bytes of value 0x00,
       then processed as above.
    2. The resulting sequence of characters is truncated to its
       first two characters (if the group initially contained a single
       byte) or to its first three characters (if the group initially
       contained two bytes).

A B64-encoded value thus yields a string whose length, taken modulo 4,
can be equal to 0, 2 or 3, but not to 1. Take note that a sequence of
characters of the right length may still be an invalid encoding if it
defines some non-zero trailing bits in the last incomplete group;
producers MUST set the trailing bits to 0, while consumers MAY ignore
them, or MAY reject such invalid encodings.


### Decimal Encoding

For an integer value _x_, its decimal encoding consist in the following:

  - If _x_ < 0, then its decimal encoding is the minus sign `-` followed
    by the decimal encoding of -_x_.
  - If _x_ = 0, then its decimal encoding is the single character `0`.
  - If _x_ > 0, then its decimal encoding is the smallest sequence of
    ASCII digits that matches its value (i.e. there is no leading zero).

Thus, a value is a valid decimal for an integer _x_ if and only if all of
the following hold true:

  - The first character is either a `-` sign, or an ASCII digit.
  - All characters other than the first are ASCII digits.
  - If the first character is `-` sign, then there is at least another
    character, and the second character is not a `0`.
  - If the string consists in more than one character, then the first
    one cannot be a `0`.

The C function `strtol()` and `strtoul()` can decode decimal values if
their `base` parameter is set to 10.


### Function Duties

A password hashing function that uses this specification for its salt
and hash strings MUST specify the following:

  - The function symbolic name.

  - The unique order in which parameters may appear.

  - For each parameter:
    * the parameter name;
    * the set or range of acceptable values for the parameter;
    * the deterministic encoding of the parameter;
    * the maximum size (in characters) of the encoded parameter value;
    * whether the parameter is optional, and, if yes, its default
      value when not encoded.

  - The set of valid salt values, in particular minimum and maximum
    length (in characters, and in bytes when applicable).

  - The minimum, maximum and default output lengths (in bytes, and in
    characters after encoding).


It is RECOMMENDED to follow these guidelines:

  - The function name, and the parameter names, should promote
    readability. (Note that readability depends a lot on who is doing
    the reading, and there is no universal definition of that property.)

  - Making parameters optional means that human readers must know what
    value a parameter has when it has been omitted. Parameters for
    optional features (e.g. some explicit "additional data") are most
    naturally made optional; other parameters such as number of
    iterations are best kept specified explicitly.

  - Maximum lengths for salt, output and parameter values are meant to
    help consumer implementations, in particular written in C and using
    stack-allocated buffers. These buffers must account for the worst
    case, i.e. the maximum defined length. Therefore, keep these lengths
    low.

  - The role of salts is to achieve uniqueness. A _random_ salt is fine
    for that as long as its length is sufficient; a 16-byte salt would
    work well (by definition, UUID are very good salts, and they encode
    over exactly 16 bytes). 16 bytes encode as 22 characters in B64.
    Functions should disallow salt values that are too small for
    security (4 bytes should be viewed as an absolute minimum).

  - The hash output, for a verification, must be long enough to make
    preimage attacks at least as hard as password guessing. To promote
    wide acceptance, a default output size of 256 bits (32 bytes,
    encoded as 43 characters) is recommended. Function implementations
    SHOULD NOT allow outputs of less than 80 bits to be used for
    password verification.


## API

The traditional Unix crypt() function is used both for password
registration, and for password verification. It uses two string
parameters:

       char *crypt(const char *key, const char *salt);

The `key` is the password, while `salt` is a salt string or a hash
string. In order to be compatible with how the crypt() function is
used in existing software, the following must hold:

  - If `salt` is a salt string (no output), then the function must
    compute a hash output whose length is the default output length for
    that function. The returned string MUST be the strict, deterministic
    encoding of the used parameters, salt and output.

  - If `salt` is a parameter string (no salt nor output), then the
    function must generate a new appropriate salt value as mandated by
    the function specification (e.g. using the defined default salt
    length), and then proceed as in the previous case. The returned
    string MUST be the strict, deterministic encoding of the used
    parameters, salt and output.

  - If `salt` is a hash string, then the function must compute an output
    with exactly the same length as the one provided in the input. The
    output is then the concatenation of the parameters and salt _as they
    were received_, and the newly computed output. Basically, the
    function truncates the `salt` string at its last `$` sign, then
    appends the recomputed output.

The third case departs from the prescription that string producers must
always follow the deterministic encoding. This is done that way in order
to support the common case of password verification: the `salt` value is
the complete hash string as it is stored; the hash is recomputed, and
the caller verifies that the exact same string is obtained (e.g. with a
`strcmp()` call). This is the reason why the parameters and salt are
reused "as is" in the output, even if they do not match the
deterministic encoding prescribed in this document.

On the other hand, when the input `salt` string does not include the
hash output, then this is initial registration, and we insist on using
the unique valid deterministic encoding. The whole point is to try to
avoid local variations that are detrimental to interoperability, while
not breaking existing password hashes.


## Argon2 Encoding

For Argon2, the following is specified:

  - The identifier for Argon2d is `argon2d`.

  - The identifier for Argon2i is `argon2i`.

  - The identifier for Argon2id is `argon2id`.

  - The versions are: [16, 19].
  
  - The parameters are:

    * `m`: Memory size, expressed in kilobytes, between 1 and (2^32)-1.
      Value is an integer in decimal, over 1 to 10 digits.

    * `t`: Number of iterations, between 1 and (2^32)-1.
      Value is an integer in decimal, over 1 to 10 digits.

    * `p`: Degree of parallelism, between 1 and 255.
      Value is an integer in decimal, over 1 to 3 digits.

    * `keyid`: Binary identifier for a key. Value is a sequence of 0
      to 8 bytes, encoded in B64 as 0 to 11 characters. This parameter
      is optional; the default value is the empty sequence (no byte at
      all) and its meaning is that no key is to be used. The contents of
      the identifier are chosen by the application and are meant to
      allow the application to locate the key to use.

    * `data`: Associated data. Value is a sequence of 0 to 32 bytes,
      encoded in B64 as 0 to 43 characters. This parameter is optional;
      the default value is the empty sequence (no byte at all). The
      associated data is extra, non-secret value that is included in the
      Argon2 input.

    The parameters shall appear in the `m,t,p,keyid,data` order.
    The `keyid` and `data` parameters are optional; the three others
    are NOT optional.

  - The salt value is encoded in B64. The length in bytes of the
    salt is between 8 and 48 bytes(*), thus yielding a length in
    characters between 11 and 64 characters (and that length is never
    equal to 1 modulo 4). The default byte length of the salt is 16
    bytes (22 characters in B64 encoding). An encoded UUID, or a
    sequence of 16 bytes produced with a cryptographically strong
    PRNG, are appropriate salt values.

    ((*) the Argon2 specification states that the salt can be much
    longer, up to 2^32-1 bytes, but this makes little sense for
    password hashing. Specifying a relatively small maximum length
    allows for parsing with a stack allocated buffer.)

  - The hash output is encoded in B64. Its length shall be between
    12 and 64 bytes (16 and 86 characters, respectively). The default
    output length is 32 bytes (43 characters).
