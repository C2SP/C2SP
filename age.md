# age

[c2sp.org/age](https://c2sp.org/age),
[age-encryption.org/v1](https://age-encryption.org/v1)

age is a modern file encryption format with multiple pluggable recipients, and
seekable streaming encryption.

## Conventions used in this document

ABNF syntax follows [RFC 5234][] and [RFC 7405][] and references the core rules
in RFC 5234, Appendix B.1.

The base64 encoding used throughout is the standard Base 64 encoding specified
in [RFC 4648][], Section 4, without `=` padding characters (sometimes referred
to as "raw" or "unpadded" base64). Encoders MUST generate canonical base64
according to RFC 4648, Section 3.5, and decoders MUST reject non-canonical
encodings and encodings ending with `=` padding characters.

Keys derived with HKDF-SHA-256 are produced by applying HKDF-Extract with the
specified salt followed by HKDF-Expand with the specified info according to
[RFC 5869][]. The hash used with HKDF in this specification is always SHA-256.
The length of the output keying material is always 32 bytes.

ChaCha20-Poly1305 is the AEAD encryption function from [RFC 7539][].

Bech32 is as specified in [BIP173][], but without length limits on the data
part. Note that Bech32 strings can only be all uppercase or all lowercase, but
the checksum is always computed over the lowercase string.

`||` denotes concatenation. `0x` followed by two hexadecimal characters denotes
a byte value in the 0-255 range. `[:N]` denotes truncation to the first N
bytes of a byte string.

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in [BCP 14][] [RFC 2119][]
[RFC 8174][] when, and only when, they appear in all capitals, as shown here.

## Encrypted file format

An age file is composed of two parts: a textual [header](#header) that carries
the _file key_, and a binary [payload](#payload) encrypted with it. Overall, age
files MUST be treated as binary, and are not malleable without knowledge of the
file key.

age files MAY use the extension `.age`, in both their binary and
[armored](#ascii-armor) formats.

### File key

Each file is encrypted with a 128-bit symmetric _file key_.

The _file key_ MUST be generated as 16 bytes of CSPRNG output. It MUST NOT be
reused across multiple files.

### Header

The textual file header wraps the _file key_ for one or more _recipients_, so
that it can be unwrapped by one of the corresponding _identities_. It starts with a
version line, followed by one or more recipient stanzas, and ends with a MAC.

    age-encryption.org/v1
    -> X25519 XEl0dJ6y3C7KZkgmgWUicg63EyXJiwBJW8PdYJ/cYBE
    qRS0AMjdjPvZ/WT08U2KL4G+PIooA3hy38SvLpvaC1E
    --- HK2NmOBN9Dpq0Gw6xMCuhFcQlQLvZ/wQUi/2scLG75s

Note that each section of the header can be parsed by looking at its first three
characters, and it ends either at the next newline (for version and MAC lines)
or at the first line shorter than 64 columns (for stanzas).

#### Version line

The version line always starts with "age-encryption.org/", is followed by an
arbitrary version string, and ends with a line feed (`0x0A`).

    version-line = %s"age-encryption.org/" version LF

    version = 1*VCHAR

This document only specifies the `v1` format. Anything after the end of the
version line may change in future versions.

#### Recipient stanza

A recipient stanza starts with `->`, followed after a space by one or more space-separated
arguments, and a base64-encoded body wrapped at 64 columns. The body MUST end
with a line shorter than 64 characters, which MAY be empty.

Each recipient stanza wraps the same _file key_ independently. Identity
implementations are provided the full set of stanzas and recognize those
addressed to them from their arguments. Identity implementations MUST ignore
unrecognized stanzas, unless they wish to require that the recipient type they
implement is not mixed with other types.

It is RECOMMENDED that non-native recipient implementations use fully-qualified
names as the first stanza argument, such as `example.com/enigma`, to avoid
ambiguity and conflicts.

Recipient implementations MAY choose to include an identifier of the specific
recipient (for example, a short hash of the public key) as an argument. Note
that this sacrifices any chance of ciphertext anonymity and unlinkability.

#### Header MAC

The final header line starts with `---` and is followed after a space by the
base64-encoded MAC of the header. The MAC is computed with HMAC-SHA-256 (see
[RFC 2104][]) over the whole header up to and including the `---` mark
(excluding the space following it).

The HMAC key is computed as follows:

    HMAC key = HKDF-SHA-256(ikm = file key, salt = empty, info = "header")

#### ABNF definition of file header

The following is the ABNF definition of the v1 file header.

    header = v1-line 1*stanza end

    v1-line = %s"age-encryption.org/v1" LF

    end = "--- " 43base64char LF

    base64char = ALPHA / DIGIT / "+" / "/"

    stanza = arg-line *full-line final-line

    arg-line = "-> " argument *(SP argument) LF

    argument = 1*VCHAR

    full-line = 64base64char LF

    final-line = *63base64char LF

### Payload

The binary payload encrypts the file body and starts immediately after the
header. It begins with a 16-byte nonce generated by the sender from a CSPRNG.
A new nonce MUST be generated for each file.

The payload key is computed as follows:

    payload key = HKDF-SHA-256(ikm = file key, salt = nonce, info = "payload")

The payload is split in chunks of 64 KiB, and each of them is encrypted with
ChaCha20-Poly1305, using the payload key and a 12-byte nonce composed as
follows: the first 11 bytes are a big endian chunk counter starting at zero and
incrementing by one for each subsequent chunk; the last byte is 0x01 for the
final chunk and 0x00 for all preceding ones. The final chunk MAY be shorter than
64 KiB but MUST NOT be empty unless the whole payload is empty.

This is a STREAM variant from [Online Authenticated-Encryption and its
Nonce-Reuse Misuse-Resistance][STREAM]. It is similar to those used by [Tink][]
and [Miscreant][], but it doesn't prefix the AEAD nonce with key material as the
payload key is 256 bits (enough even to provide a security margin in the
multi-target setting) and derived from both file key and nonce.

The payload can be streamed by decrypting or encrypting one chunk at a time.
Streaming decryption MUST signal an error if the end of file is reached without
successfully decrypting a final chunk.

The payload can be seeked by jumping ahead in chunk increments, and decrypting
the whole chunk that contains the seeked position. Seeking relatively to the end
of file MUST first decrypt and verify that the last chunk is a valid final
chunk.

The payload MUST NOT be modified without re-encrypting it as a new file with a
fresh nonce.

## Native recipient types

This document specifies five native age recipient types: a hybrid post-quantum
asymmetric encryption type based on X-Wing, an asymmetric encryption type based
on X25519, a passphrase encryption type based on scrypt, and two tagged
recipient types based on ML-KEM and P-256 ECDH for hardware keys.

### The MLKEM768-X25519 (i.e. X-Wing) hybrid post-quantum recipient type

An MLKEM768-X25519 identity is generated as

    identity = read(CSPRNG, 32)

and encoded as Bech32 with HRP `AGE-SECRET-KEY-PQ-`.

    AGE-SECRET-KEY-PQ-1XX76JRALNLXDMEW0CRK45QMCCH4X06SE84UN3VPM33W6HWDX0H3SK3ZQFR

The corresponding recipient is computed as

    recipient = PrivateKeyToPublicKey(identity)

where PrivateKeyToPublicKey is as specified in [filippo.io/hpke-pq][] for the
MLKEM768-X25519 hybrid HPKE KEM.

The recipient is encoded as Bech32 with HRP `age1pq`.

    age1pq1x34nzsvr0rxjsgdn8zgyhfe8j7ceq5r9rdelkjuh3y235jzxshfg87pzf5zrqtzdxz95paef6caq5aapdmwjjqpjfdyxnzr2zampc3uxy0dg4z2n2gm9su72p0pc3u0jvev55l694v78snxg3yzvcl7yda0eyytqj6a0ec477lnhcy5hzpz4zq3pxanve4cn62gqj3pjy5lqj9c6kyj4v2z8alktn8zh99970x79gjkv7522hv9kfz35zsnxhsx8wwtmu9cy3ftzjgwcp4sshn3llnylnpdsyz5jm72vefv4x5vfwytrefxg4wq3mv42wcrvkj742479zrxzpvp2p3e9fed9f0739vcu80r7ma28qfhnvlv4gfzel9q654dj3zmuvvz893azhxdvs9fxd0r7jzchzcfcs5mkyyjxhw0n2z6dvp9yn9qfdp29h0azxqyjw6v7fhyuzj7zel0uq6j9rd7wgrpz7mf5dnj43jwsgvrc8qcnhy7tu6dkdujuxzkp9xj43xe8h92ktre2a3u3s8mm5mrp9nr9pwkgtz4mdlq9hgn4fps4k57ff6wddn2fy23t47sm20r8km8sd2pcyyafnet8f0dajsrlyjeah4n3mssr6aseevuuskdvq5lzguyvpgwpta742c6698vgutzqgny8usfg0w2he7kq5vyxjd0f9hqg8xk26y9e4th0gezq92q4cpp5p2y9hf5f2cje5l0c3sa3a2qxmm38pxxvhxh99yzmfz0zk7r2s64nnwjhkfgfr3gf8xnmppcgmaykvh5sh6g7vk9790rf8ws0axmr2t7z8aae5fq2029uvcn2ghgt4fu4wgwdc0k0cz52qkvwmuzj8p8k5jgf3xzk5zmrkavjekjrpeq408xz3zxazwkc6tyfmhayrkfpjhwtz5mp8j8guqe43k2q6m2kte03vrw27y3wmqyu5etmt9dnkwcnnpmu9gz9dekfhdevf42ucshphnrk38ra6hx8w5f8q5ru0xdhrjxmwqf6cused7zc5xvq43r0zscjglpwlptpwydhqw64xz7ptjdyeyzpq2zkxtmzg29gzjpvzva4d3l0cenn9xs297wf4y4ukwrunf57xj6pm7nvrkwvtrt8hwcmgv8x7ajw7258ugf9wvkmk4052ekg87tw5vnx8nq2swyzv77v8yqlwsenvamr0zssknwts8rrhfuwj7ykysnq9jxy0uv3kuyt22djszjdtvpz6d0s0kwh8ryynddzud92emeyvvyqktd0jtj7rvvg5gch25v8smlvny3kvn5gagyz475ze2y6q466xqmz2n3hs77lddeqyta2nch5k2u5yacuk9ywnwfdzvyejnucz724hj77hrrmakm7pr3kxsrxq22ejexlud9fy2kdqmkg5yncz7jm5wv2qjk5w5kvcpqsry2yqffh2la52dxfjkjq5rzhjzeyn6dupn0qwtyv7s4lwg3xdarsdlwe2y3tujy480y7z39q259fzx6jhd2j0f5hagqpcpees7hzc2yrk5cy788uk3s7qvp5cpepx24gvws3m2g433exgwppnkjscec8qu4y9z9r7vccexjcjaen42245lmgmxmuavg9alej92322gvvyy2t6267v09ch64y0m53jff0vjj96s0ypk60hr3jw4myd6m5hpn3xjstx7tl2szhpr5qe8jj08ydjc4wy2rch2fhuy3pdfjax5awe9j99ly5hkntzz9fe5zatgjvzdd0kgtxs25njnajyf6ssekp7gelxquusn4pt25czh3scj68kq79wdn5tgm6yvm9nzavrg043x3msnygf8dweknw5jmqd0uvny6ttsn09508k0c55zfnegrm9efhxpfqdkmhh6gjtqmwze9pyyzk3tlhl53k2ykx3qheyty7saeq0d3fzv49zc0k

This recipient type is secure against future cryptographically-relevant quantum
computers, so the same file SHOULD NOT be encrypted to both this recipent type
and to other non-quantum-resistant recipient types.

#### mlkem768x25519 recipient stanza

To produce a mlkem768x25519 recipient stanza, the file key is encrypted with
the HPKE SealBase function from [RFC 9180, Section 6.1][] with the following
parameters:

  * KEM: MLKEM768-X25519 from [draft-ietf-hpke-pq-03][]/[filippo.io/hpke-pq][]
  * KDF: HKDF-SHA256
  * AEAD: ChaCha20Poly1305
  * `pkR = recipient`
  * `info = "age-encryption.org/mlkem768x25519"`
  * `aad = ""` (empty)

It is then encoded as a recipient stanza with two arguments: the first is the
fixed string `mlkem768x25519`, and the second is the base64-encoded encapsulated
key *enc* from SealBase.

The body of the recipient stanza is the HPKE ciphertext from SealBase.

    -> mlkem768x25519 U7E10Aon27j1oDrH7fP3B++SPROSnDVvQpBemzOM+ZcsojxJifUbeeYWejMYKNB+H3rlXNvgtDKfSCkt78oqncr3faY1JtMj0GQPBZ2g6t8o1cMzZgyLMepeVuTQKxLqnM6L48n8dJL2y0N3i7WSOV6csB79r9tcIs88Al9iCwVLpt74OzDXAIwD1QlCAvj75ZEnwtgP6Xr6s+wHg9hLD0OSSQOaTdCqzR5shQWyrjVs7GCqd/5WbNGYNaolPQJBu9wTNhHjP9XGCTv8iKXkYwXDYujInkF5hOjpCHE8Vu+9UeMI+l0GJAEervT51bwaf288GiqgapP5g4HF8V4P0+03B/SwXhvxxZpKjTU2OcFS8I9chtEZ7Ucw5bvPkC1lyjNnqQXZyc4JnAqbFQTlPGnwbEsm0UGE+v0FOxTBznIivHoPHV++5PuYpombiV/lfYy8BFx0Hk1igNI3iLNjlIg4MLXNWjN3VROlXIiSsWNXjr/Frh/OE87PXoaKhsDPWfv6akd9PxSDqJMQ4j8k11kCSOnnU8Rw4TSVnTpt7gfYzBULrMr7qDgyH/TYvp0o7mAq4IaraFJmTqm+LjfAJT4PCQOpnMNRHLyXZn6mtMUujNv7+zR/I9Vqi+bJdQBwNWdJcUQVarqx2zxV2rM7l+j0gsmxjxp5yAPyALzla7XzVvbboLMnHeM+CzN4GoB2PC4neVDSw7Dfs8vbm7f9CeDGvhjWrzcSCOsUCalvH1WkbpE0b9cE/TSJqwXFXEc8npTSQWH58RXDALNF3qCbW5LaboD4wCloClEakgljT0s0mTdqIwzj4xtdlX0S2dCtaV5MHQJiQHGwPvBSCiIsh8ZWJPwZ7Ron7xoWgNI0lXRqhKm7fvFNCzF+Ray2kOyKWHbsMy3a5Zx3yZxCGFwexAxgYfAH9HJ1raHi1XYGpNpBlDXg47U1y4uU7RBeBb4ewETv/B/p8sGW88tIY87dHM2xHjnntGXLvkCIkmjXGNULAVYHxDPJTygxSF7uTVPYCBUk5KeLnDVcgWF8p/wxigza47ptMtpVtm9ZrSEu9vzOnaTN3KO75RkkLuZszhXfmMZ46NQrdS7Y6duCiN501BnR5BUC4dX4iMxchix6aLN3pKv6UOEwwcx2aSF4Ib963MAtTPEjhqe+dt0VcTar/08uLWv1kQQueFaEGet4KQ975ZqaoU3PmZH9gqTOumX1EKf0Pnl0F3NMW+lEOlnCEce99zHBwBf7LV0pLNLDONBxpQySrZUQsNfhAq2Ktf5nG2hcGAMFMWIsEOuOyzEe+l2aHW4/ojOjU1Oqy4TLzVVRlWmPxQde7qKbvBN7CQhDqJHJA2nphQT/4DOdLqkwRiauMmnfx9FI3+hYnX25NpnyvM/Pt94vpsRkhcuttu4/G4xOYTNQd2YWjGwhypZ0oPSiriuTbhj6y2qm33jiwxvegeDz8CmAIhOEY2JoVpjjX9XzuNR2f5KTLmLzEkOcJQ
    c/k+TjhBA6Je1DF8rxZhe2Jm8CN0zbkV9rre6nA8g98

The file key can be decrypted with OpenBase from HPKE with the same parameters
as above, and `skR = identity`.

The identity implementation MUST ignore any stanza that does not have
`mlkem768x25519` as the first argument, and MUST otherwise reject any stanza
that has more or less than two arguments, or where the second argument is not a
canonical base64 encoding of a 1120-byte value. It MUST check that the body
length is exactly 32 bytes before attempting to decrypt it, to mitigate
partitioning oracle attacks.

### The X25519 recipient type

An X25519 identity is generated as

    identity = read(CSPRNG, 32)

and encoded as Bech32 with HRP `AGE-SECRET-KEY-`.

    AGE-SECRET-KEY-1GFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPYYSJZGFPQ4EGAEX

The corresponding recipient is computed as

    recipient = X25519(identity, basepoint)

where `X25519` is from [RFC 7748][], Section 5, and `basepoint` is the
Curve25519 base point from RFC 7748, Section 4.1.

The recipient is encoded as Bech32 with HRP `age`.

    age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj

#### X25519 recipient stanza

An X25519 recipient stanza has two arguments.

    -> X25519 O6DLx/wDIawpUC978NSPjYvrfDtJVnZApXKp4FMPHCY
    3aKjozt9agh7jGmvOKvR4iax41Wl4zj95MKK4X9JuWc

The first is the fixed string `X25519` and the second is the base64-encoded
ephemeral share computed by the recipient implementation as follows:

    ephemeral secret = read(CSPRNG, 32)
    ephemeral share = X25519(ephemeral secret, basepoint)

A new ephemeral secret MUST be generated for each stanza and each file.

The body of the recipient stanza is computed by the recipient implementation as

    salt = ephemeral share || recipient
    info = "age-encryption.org/v1/X25519"
    shared secret = X25519(ephemeral secret, recipient)
    wrap key = HKDF-SHA-256(ikm = shared secret, salt, info)
    body = ChaCha20-Poly1305(key = wrap key, plaintext = file key)

where the ChaCha20-Poly1305 nonce is fixed as 12 0x00 bytes.

The identity implementation MUST ignore any stanza that does not have `X25519`
as the first argument, and MUST otherwise reject any stanza that has more or
less than two arguments, or where the second argument is not a canonical base64
encoding of a 32-byte value. It MUST check that the body length is exactly 32
bytes before attempting to decrypt it, to mitigate partitioning oracle attacks.

The identity implementation computes the shared secret as follows:

    shared secret = X25519(identity, ephemeral share)

If the shared secret is all 0x00 bytes, the identity implementation MUST abort.

Finally, it derives the key as above and decrypts the file key in the body.

### The scrypt recipient type

The scrypt recipient and identity implementations encrypt and decrypt the file
key with a provided passphrase.

#### scrypt recipient stanza

An scrypt recipient stanza has three arguments.

    -> scrypt ajMFur+EJLGaohv/dLRGnw 18
    8SHBz/ldWnjyGFQqfjat6uNBarWqqEMDS7W8X7+Xq5Q

The first is the string `scrypt`, the second is a base64-encoded salt computed
by the recipient implementation as 16 bytes from a CSPRNG, and the third is the
base-two logarithm of the scrypt work factor in decimal.

A new salt MUST be generated for each stanza and each file.

The body is computed as

    wrap key = scrypt(N = work factor, r = 8, p = 1, dkLen = 32,
        S = "age-encryption.org/v1/scrypt" || salt, P = passphrase)
    body = ChaCha20-Poly1305(key = wrap key, plaintext = file key)

where the ChaCha20-Poly1305 nonce is fixed as 12 0x00 bytes and scrypt is from
[RFC 7914][].

The identity implementation MUST reject any scrypt stanza that has more or less
than three arguments, where the second argument is not a canonical base64 encoding of a
16-byte value, or where the third argument is not a decimal number composed of
only digits with no leading zeroes (`%x31-39 *DIGIT` in ABNF or `^[1-9][0-9]*$`
in regular expression). The identity implementation SHOULD apply an upper limit
to the work factor, and it MUST check that the body length is exactly 32 bytes
before attempting to decrypt it, to mitigate partitioning oracle attacks.

An scrypt stanza, if present, MUST be the only stanza in the header. In other
words, scrypt stanzas MAY NOT be mixed with other scrypt stanzas or stanzas of
other types. This is to uphold an expectation of authentication that is
implicit in password-based encryption. The identity implementation MUST reject
headers where an scrypt stanza is present alongside any other stanza.

### The tagged recipient types

The tagged recipient types are designed for hardware keys, where decryption
potentially requires user presence. With knowledge of the public key, it is
possible to check if a stanza was addressed to a specific recipient before
attempting decryption. (This offers less privacy than the default recipient
types.) The tagged recipient types are based on HPKE, and use P-256 ECDH for
compatiblity with existing hardware, optionally hybridized with ML-KEM-786
for quantum resistance.

This document only defines the recipient encodings, and does not define how the
corresponding identities are generated or encoded. We expect these recipients to
be used as the public side of hardware-specific plugin identities.

The non-hybrid recipient is a P-256 curve point serialized as 33 bytes with the
*compressed* Elliptic-Curve-Point-to-Octet-String conversion from [SEC 1, Ver.
2][] and encoded as Bech32 with HRP `age1tag`.

    age1tag1qt8lw0ual6avlwmwatk888yqnmdamm7xfd0wak53ut6elz5c4swx2yqdj4e

The hybrid recipient is an ML-KEM-768 encapsulation key concatenated with an
*uncompressed* P-256 curve point (unlike the non-hybrid recipient), for a total
of 1249 bytes, and encoded as Bech32 with HRP `age1tagpq`.

    age1tagpq1m3e4wvp6hzcrn9exhy0ae3xfx2sjymp594k3tg7j4dpmj922we65vtnmrt2pyallax8669zqkr2pmfchptr4n38kug2xmcmp3adk2lnjqu00x5kxz5pvhmrltvfh9wuq973pcx35cnq8syn9qd3tzpehgztl4xpzr3tpd67g8af9trnjpc05gh7wu536aq4qt2y8zhsm4tvrfpsfl36qs5fpzysnk3sp9w77qzeg49357xex40v4s2lvt620swyys7u8yxdcnu4rkkwxdmt55gsuc3h5c5swahnegjgqwc60hn085ec3sjztwm45l44y3j2at9t6v9zra4ek3kek6waecqm98yaxl37w0d2zra626nz63jdm5sg59w7lyptw83zm6fntd8d0x03a9z6h9prfgpygzar6zrxjcrt4cdctk2mhf95s4a6v4zklfd49xhpsaeujm57thx2x3e3hwzc86ftfhmq5mkxxz3d6r8ws24xj4qfn73eyezg2wy094e3why592pghz27ruq3vkyegrv80eftnw9wqzwgvnwyseaus0yt84fylzrpzp6x2fguxuqjmgudr8xd33qm30evdpxd3jvjg8qh4q60kyq80jgff369k7nrepdc38grd2dava520excqp0ey0x39khx8ry03yffcatgv84fsx5j49djpapedsy693zute5xv5g2ewzrlj5se7akvkc4g4vmzhputpq8eyj9wz5dz6qtn7g3cfpd95nahw4ytspan0feyye04dcylv24ege7zkaj004gjwcxqxfqu2quawa83sx452jqjn8t48czp0xspwgnmvjyhttzzy6nhq8xzkdwnvsfefkwva6asrqc93zjn4rly5gnlv93xy3uzmr39szvjnf63426qzyeyvguc4vdcquwgsxgq236afcpqz866ny4tn7ckc0umefj242rt5vtvwqzzrvfev2mpvqcufp9pqvefyv4ftyuhgausfzuaadsczeykmft5wv3frzgrcp9ztr93h478ke4t86spp2uhyjkj73mp9g92ddk2fpv7v3njzsqgwhq3789sqrgkskehn0zjscckhwftyq4vet7vrlx2hs5kd9cwnq6t0djffhh3zquh4j3p0yaj9z2rc9wykg0usqw7983rrgur9jg8rnnqypwcz2lyclnnc705fc5g3an93ps60q6mxqp85u0ewtxdjlqcks84yduft0a0g6e7naew3v9u2d08knarvajn8q3gq9pgxde3s7nx94lus48wwvw2xjm7k82tvylec2393jdsuvch2xpe77w8hpv9nvsxfsrs270njpmfvpmgyk2cffl9tjp3qqcc4dfkf5rme2dg0x7ew8g39www5smm705q5da4eqvnqwrkavtq6xje9ss38hnkglz4eddz8f5qruvqmq2ff9l22gwkv8h432rdkysy0grkul8e2fedvkyyapfxt760udcgu92m54wl9yavmj4ga3ph9r5n99cjrq6wj5v33x33fe5vkjvfwnnt40wuv2hyexc9f4ylyqv9ldqq9epd4yuv8vrsfx2qy2kqz08kqhnzspy6s0x8fa5c2xkg5y2q0rvz4vnk7rp0acg6eksc3t7cxnn8y7glkjsqja3p56uz6vvhcw55d3ysad0hvsqxpjnc7svenf2gc5xn5kyr0et2vvyruxlnpqcdpqh9pzplumy5yzjxftyzh9ujfw0jq7ee60zx2x23p0jzyh9dvmly8p9h9ysptlqu7kwnejd65dnr75a0np2fvke8xen38r57w6z3wz3mycjmmn267wwxndfh9jdps7uxtct2wwfgamkpa5ap8s96lhfjztpwcm6fguhphu38yunu2v4vz3syzrvgwtqpemkewzp766nyu6texxvjlaemnhyyqutkcy6a42vqfsz49rw5wr4gt70r4vdaasehqjg46fnyts4sthrxadfllha3avu49wsj2c4jx

The hybrid recipient is secure against future cryptographically-relevant quantum
computers, so the same file SHOULD NOT be encrypted to both a hybrid recipient
and to other non-quantum-resistant recipient types.

The recipient encodings can be interpreted as plugin recipients with names `tag`
or `tagpq`, allowing for backwards compatibility with existing clients through
plugins.

#### p256tag recipient stanza

To produce a p256tag recipient stanza, the file key is encrypted with the HPKE
SealBase function from [RFC 9180, Section 6.1][], with the following parameters:

  * KEM: DHKEM(P-256, HKDF-SHA256)
  * KDF: HKDF-SHA256
  * AEAD: ChaCha20Poly1305
  * `pkR = decompress(recipient)` (the uncompressed P-256 point)
  * `info = "age-encryption.org/p256tag"`
  * `aad = ""` (empty)

The recipient MUST be converted from its compressed form to uncompressed form
before being used with HPKE's DeserializePublicKey function.

The result is then encoded as a recipient stanza with three arguments: the first
is the fixed string `p256tag`, the second is the base64-encoded tag, and the
third is the base64-encoded encapsulated key *enc* from SealBase.

    tag = HKDF-Extract-SHA-256(ikm = enc || pkR, salt = "age-encryption.org/p256tag")[:4]

Note that the ikm of the tag computation matches the kem_context of the HPKE
Encap and Decap functions.

The body of the recipient stanza is the HPKE ciphertext from SealBase.

    -> p256tag CXBuUw BOqTylUtZFwkMTxd6UENg8kopiMhRJBOUXMv5w2xVOmJu7eezoALGXiNtq5Vka+UQvaYbQvAdwjIJEDaoBaq7So
    bZQpLsV8uGqGPs70J6dVodiHejsZ5BODjaRsB0RcBqI

The identity implementation MUST ignore any stanza that does not have `p256tag`
as the first argument, and MUST otherwise reject any stanza that has more or
less than three arguments, or where the second argument is not a canonical
base64 encoding of a 4-byte value or the third argument is not a canonical
base64 encoding of a 65-byte value. It MUST check that the body length is exactly
32 bytes before attempting to decrypt it, to mitigate partitioning oracle attacks.

#### mlkem768p256tag recipient stanza

To produce a mlkem768p256tag recipient stanza, the file key is encrypted with
the HPKE SealBase function from [RFC 9180, Section 6.1][] with the following
parameters:

  * KEM: MLKEM768-P256 from [draft-ietf-hpke-pq-03][]/[filippo.io/hpke-pq][]
  * KDF: HKDF-SHA256
  * AEAD: ChaCha20Poly1305
  * `pkR = recipient`
  * `info = "age-encryption.org/mlkem768p256tag"`
  * `aad = ""` (empty)

The result is then encoded as a recipient stanza with three arguments: the first
is the fixed string `mlkem768p256tag`, the second is the base64-encoded tag, and
the third is the base64-encoded encapsulated key *enc* from SealBase.

    tag = HKDF-Extract-SHA-256(ikm = enc[1088:] || recipient[1184:], salt = "age-encryption.org/mlkem768p256tag")[:4]

Note that the ikm of the tag computation only includes the P-256 component of
the encapsulated key and recipient (since the ML-KEM encapsulation key might not
be available without user presence, depending on how it is stored on the
hardware).

The body of the recipient stanza is the HPKE ciphertext from SealBase.

    -> mlkem768p256tag Ke5Xmw xCwuu/DaqxpCEA6pOJO1rLO4BG+BCgL7jG3r50doA/Ns/HWS6zvgvDWPX+4qCBgwldrp3OwYn5baW9CTkDqgWTCcTUDdfZW9v/CP+Hw68XNUOVRLd3gJrIXSSJlw+pW87xQLJrn0QRykKmBgaBoV9JHV0w0mkcCq6Hyv5gvP6ZG/3Xd384pTVTl67Qj9YhBTn0haURN/F0QkBol0PmcDYje14+UU6lM/juXPs/gdZqKCyWVunlvDSKCyHwGL0sJP1oqNtwhyTkVh04x66+2u0yNxc0byfbx522AZZJdSGP1RfR855/tyNJLo2C5k1meSL78vBkuZk9eUEvyoPbK3KIl7D9dcZR93ECoHPeDBUQKNo6uzvAC8OmpU9NsJ3i/9Is36+0MbB5AZtFdSb4L6gw/ecPhK4vl85nRL5Yq1BkWXlrYsXltoStsbMBvV/xOPwsrMrUqGATrR5zypN9wVsi4xrtQYp5Qy2a7ZewzgiktO+lWGWR5n3ik4rN3/SgkeFE1/QRJFns81oV/Vqm6OaCzS3FM4jjjcAgqqJG+EGKCbOEG28xIbRuAyRX+TR/7JGlPRqgdMMTNv5LoB//hY6pUQq/zRFh2UgmtM7dWcuSB1BJ+2tH+S7IssErO2l/1Yj2363QuKozVLpHwL2mt3vV8j3aefWHIZPlX+kxdC/YEGRkRjN23eeozQFvLbVJjU4GWoJb++q8HYRNxLLRwfvOACzKj8I61OIfhzK9ho58lgtENYD43n+C+Z16t4nG3stUBvzgWKohOLJXL/AxOgghvrpkgzOYZl1E1LTWqWRqz//0bESfCziZlKrwJw117/orYjDCBpAtgHSdBiLU724oumOSq+A8TwBjHSTkZc2L3CNul1ENhxxOeKj5KUKy0bMgIJSIdUtBfgGJPLzsrMxyw/3B2H2Jx7F0zY0crWMc/1ok7MxFT+a7UJguRK15lHmWoqKZPh1KEJ2L/BkMSYh2IWlQAg1OAq4OfhaIL3RTHHkihhciY4B9U9iok+dfco/cmFALEzPjkVSNPT0Q0st5y5G++zz/K4/KWjfYqdSnTawnecASDXcQB+AcVc88fyQpfAHC3i2JNSyJVoGhEy8gdiJzshS6enDl+4WDaIOXS/oEQB8X4uIhY9VkRn381kS5KXBgsRvDF1HCNYuTDbYFjmcbcxmFVRX0gmNj7voazh1rgtDAjg3KwQBDDe/mltP2eGmas9lPo6PyV3F/N6iDpkCoQVRgw/mjWTsiFR8aGDEd97Ot7TmhFGSQiKXfgJeip0kLZB2/dP9Z9ctKVWa8Twx58CN/UKFku27ShdW6wilUsXdcrcrrDr9BWTP1k+N6rEOVqmzfjfW7naKUPMu1cS7yCqu5Qyzkmpvq7aDB+eHR8VGzqEj9YK0HNHr+rGDcULiHT+DO7eyf8WOjHa3AaGtxq46l01/15Xh0FPM78E8JXpz8oBxelHzQSfQDfHZhQDdNdD/cB52lfs0S8xxlPrLLpA0aWImDOctYhCHB6/A1Hi5XDdDyh/NVzTGbpSOg
    PFa8qHdf8j5x6tJe7BoPCU0KGcSz1rgJO1my2ZPsJT0

The identity implementation MUST ignore any stanza that does not have
`mlkem768p256tag` as the first argument, and MUST otherwise reject any stanza
that has more or less than three arguments, or where the second argument is not
a canonical base64 encoding of a 4-byte value or the third argument is not a
canonical base64 encoding of a 1153-byte value. It MUST check that the body length is
exactly 32 bytes before attempting to decrypt it, to mitigate partitioning oracle
attacks.

## ASCII armor

age files that need to be transmitted as 7-bit ASCII SHOULD be encoded according
to the strict PEM encoding specified in [RFC 7468][], Section 3 (Figure 3), with
case-sensitive label "AGE ENCRYPTED FILE". Note that this encoding employs
base64 with `=` padding characters, unlike the rest of this document.

Note that ASCII armored files are malleable unless care is taken to reject any
data before and after the PEM encoding, a strict PEM parser is used, and
canonical base64 is enforced. age implementations SHOULD reject non-canonical
ASCII armor encodings except for whitespace before and after the PEM block, and
MAY choose to accept both LF and CRLF line endings.

## Test vectors

A comprehensive set of test vectors is avaliable at
https://age-encryption.org/testkit.

[RFC 5234]: https://www.rfc-editor.org/rfc/rfc5234.html
[RFC 7405]: https://www.rfc-editor.org/rfc/rfc7405.html
[RFC 4648]: https://www.rfc-editor.org/rfc/rfc4648.html
[RFC 5869]: https://www.rfc-editor.org/rfc/rfc5869.html
[RFC 7539]: https://www.rfc-editor.org/rfc/rfc7539.html
[BCP 14]: https://www.rfc-editor.org/info/bcp14
[RFC 2119]: https://www.rfc-editor.org/rfc/rfc2119.html
[RFC 8174]: https://www.rfc-editor.org/rfc/rfc8174.html
[RFC 2104]: https://www.rfc-editor.org/rfc/rfc2104.html
[STREAM]: https://eprint.iacr.org/2015/189
[Tink]: https://github.com/google/tink/blob/59bb34495d1cb8f9d9dbc0f0a52c4f9e21491a14/docs/WIRE-FORMAT.md#streaming-encryption
[Miscreant]: https://github.com/miscreant/meta/wiki/STREAM
[BIP173]: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
[RFC 7748]: https://www.rfc-editor.org/rfc/rfc7748.html
[RFC 7914]: https://www.rfc-editor.org/rfc/rfc7914.html
[RFC 7468]: https://www.rfc-editor.org/rfc/rfc7468.html
[RFC 9180]: https://www.rfc-editor.org/rfc/rfc9180.html
[RFC 9180, Section 6.1]: https://www.rfc-editor.org/rfc/rfc9180.html#section-6.1
[SEC 1, Ver. 2]: https://www.secg.org/sec1-v2.pdf
[draft-ietf-hpke-pq-03]: https://datatracker.ietf.org/doc/html/draft-ietf-hpke-pq-03
[filippo.io/hpke-pq]: https://filippo.io/hpke-pq
