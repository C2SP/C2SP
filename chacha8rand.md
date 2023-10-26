# ChaCha8Rand

ChaCha8Rand is a ChaCha8-based key-erasure CSPRNG with performance similar to non-cryptographic random number generators, designed to be [the default source for the `math/rand{,v2}` and `runtime` Go packages][].

It accepts a 32-bytes seed, and requires 289 bytes of state, which can be serialized to 33 bytes (see below). It’s optimized for systems with 128-bit vector math.

If the ability to serialize the state to 33 bytes is desired, the output becomes unrecoverable (in terms of forward secrecy or backtrack resistance) after at most 240 bytes of additional output are drawn. If the ability to compress the state is not necessary, it can be operated in a regular fast-key-erasure fashion.

## Description

Each iteration of ChaCha8Rand operates over 32 bytes of input and produces 240 bytes of RNG output, plus 16 bytes of key material for the next iteration.

The 32 bytes of input are used as a ChaCha8 key, with a zero nonce, to produce 256 bytes of output (four blocks, with counters {0, 1, 2, 3}). This stream is then permuted such that first we output the first four bytes of each block, then the next four bytes of each block, and so on. Finally, the first 16 bytes of output are used to overwrite the first 16 bytes of the input to produce the input of the next iteration, and the remaining 240 bytes are the RNG output.

```
stream = ChaCha8(key = input, nonce = {0}, len = 256)
output = ""
for (i = 0; i < 16; i++)
	output += stream[      i*4 :       i*4 + 4]
	output += stream[ 64 + i*4 :  64 + i*4 + 4]
	output += stream[128 + i*4 : 128 + i*4 + 4]
	output += stream[192 + i*4 : 192 + i*4 + 4]
next_input = output[:16] + input[16:]
output = output[16:]
```

## Design rationale

**Why the permutation?** On platforms with SIMD registers that can hold 128 bits, ChaCha can be parallelized four-ways (that is, producing four blocks at a time) by packing the first uint32 of state for each block in the first SIMD register, and so on. Defining the output to be permuted like in ChaCha8Rand allows producing it without having to deinterlace it, by simply concatenating the packed SIMD registers.

**Key erasure vs state compression.** Traditional key erasure involves immediately overwriting the key, and deleting buffered output bytes as soon as they are produced. An alternative strategy is deferring the overwriting until the next iteration starts, in which case the state can be serialized to just the last iteration input (from which the current buffer and the next iteration key can be regenerated) and a counter.

**“Similar performance”?** Compared to our [PCG64 DXSM](https://dotat.at/@/2023-06-21-pcg64-dxsm.html) which uses 128-bit wide multiplications, our ChaCha8Rand SIMD implementation is 25% slower on amd64, and 2% faster on arm64. It’s also faster on 32-bit 386.

**Why ChaCha8?** The goal was designing a CSPRNG fast enough that it could viably replace a non-cryptographic PRNG, so performance was a primary goal. [Too Much Crypto by Jean-Philippe Aumasson](https://eprint.iacr.org/2019/1492.pdf) provides a compelling rationale for why eight rounds are enough.

**Why overwrite only 128 bits of key?** 128 bits of overwritten seed are enough to make backtracking by brute force impossible. A 128 bits seed would not be enough in the multi-user setting (where an attacker is attempting to brute-force one of a large pool of outputs), but multi-user attacks are unfeasible due to the remaining 128 bits of the seed, which even if recovered by the attacker will differentiate the output between the multi-user population, like a nonce. Overwriting 256 bits would reduce each iteration throughput by 6%.

## Sample output

For the input `ABCDEFGHIJKLMNOPQRSTUVWXYZ123456` (in ASCII), this is the first 720 bytes of ChaCha8Rand output, as produced by the program in the `chacha8rand` directory.

```
9eba3d1c25d508280c47170635c55074af168abd29ee41b1153782a3ea01f245f4870296dfc0cf8f
2f7604b095895b0f2e3396a4e95e3286a7f36a29782fc0ae56710a83348acc6b076dd5c7174005b3
b98903bac66f206bb4944ce5e07ba619d8abeb6bf859d6f30ecb24d70a56a547dda8276c0f7f97ff
56f6449f6d313168ddf252f4f5f2eb3cf8833756a40bf0bc3e4278dc1f987fd1ff9b39f2e6334454
07b17ee9ea49292fb76c379f77531b96b7bf05e12a4ab4ef2b1e73a68973c725e82ee7c1c426d077
e4158d0d6a2ba1ea48438d70befd31d70f53586718725951278717a3395ce843448fd6b8489269ce
04b2e87371d49c4c3049a4d469318825d461d0741b29cde4816504225fa12dd7306f7ac0011736bb
db8181bf9dc92867119761ae3de9e38ce9cf64d8c1b7a69a4249906e1e6cddeee5f3afcee72998ac
cfeea1b443e309d083d8fa09da7e21611791171ea51f6f7210b04e97ef20876717e2c096fdecbb40
ee4f7d899a72a9d4a9f9dca1360b8544ca3a455fa2baccf011f7e767a233e85c577c6f0d1ee7c0d5
5b639dfbafd7bc5918d07c5f9ac9fa7b5faf809ce661bb27acc83cd4655dc92f06465e050c6a9f15
ece1b2b346cfb48c3f59d8a236d7d6b262a7d5eecb69ae412c5b069cf5e224ab9a97acdadbb19de4
df8dcadb5f3d29d01b7316d87c0e335726dfd3ee2d320faab8ba20a86a926f7e7f23049ee2eef17f
b0e9157198326445525f834a43899567122747686e45eb408b05675c7cc32ca0f06d6784461c1c0d
f020ad25c4535b423855ba2bc4f89cadeee9e556a2095521b108f7b22a0340c62b0b41b871770a31
4824e19958f0886ca282a31f08b2376648f9a442801c69886e0c7d9bcb2318fc33e23a39680a9920
51ba580d2382e299b93918a84af343ab7818abdedbe9cb4a5eaf8b6eb288438421ba40ee94fa1e98
295acd6465b1e332c21ebd45b18ce039628247921a705297811b94aef33c360a02ac12a5891fcd30
```

This is the same output interpreted as a sequence of little-endian uint64s.

```
0x2808d5251c3dba9e, 0x7450c5350617470c, 0xb141ee29bd8a16af, 0x45f201eaa3823715, 0x8fcfc0df960287f4,
0x0f5b8995b004762f, 0x86325ee9a496332e, 0xaec02f78296af3a7, 0x6bcc8a34830a7156, 0xb3054017c7d56d07,
0x6b206fc6ba0389b9, 0x19a67be0e54c94b4, 0xf3d659f86bebabd8, 0x47a5560ad724cb0e, 0xff977f0f6c27a8dd,
0x6831316d9f44f656, 0x3cebf2f5f452f2dd, 0xbcf00ba4563783f8, 0xd17f981fdc78423e, 0x544433e6f2399bff,
0x2f2949eae97eb107, 0x961b53779f376cb7, 0xefb44a2ae105bfb7, 0x25c77389a6731e2b, 0x77d026c4c1e72ee8,
0xeaa12b6a0d8d15e4, 0xd731fdbe708d4348, 0x515972186758530f, 0x43e85c39a3178727, 0xce699248b8d68f44,
0x4c9cd47173e8b204, 0x25883169d4a44930, 0xe4cd291b74d061d4, 0xd72da15f22046581, 0xbb361701c07a6f30,
0x6728c99dbf8181db, 0x8ce3e93dae619711, 0x9aa6b7c1d864cfe9, 0xeedd6c1e6e904942, 0xac9829e7ceaff3e5,
0xd009e343b4a1eecf, 0x61217eda09fad883, 0x726f1fa51e179117, 0x678720ef974eb010, 0x40bbecfd96c0e217,
0xd4a9729a897d4fee, 0x44850b36a1dcf9a9, 0xf0ccbaa25f453aca, 0x5ce833a267e7f711, 0xd5c0e71e0d6f7c57,
0x59bcd7affb9d635b, 0x7bfac99a5f7cd018, 0x27bb61e69c80af5f, 0x2fc95d65d43cc8ac, 0x159f6a0c055e4606,
0x8cb4cf46b3b2e1ec, 0xb2d6d736a2d8593f, 0x41ae69cbeed5a762, 0xab24e2f59c065b2c, 0xe49db1dbdaac979a,
0xd0293d5fdbca8ddf, 0x57330e7cd816731b, 0xaa0f322deed3df26, 0x7e6f926aa820bab8, 0x7ff1eee29e04237f,
0x456432987115e9b0, 0x679589434a835f52, 0x40eb456e68472712, 0xa02cc37c5c67058b, 0x0d1c1c4684676df0,
0x425b53c425ad20f0, 0xad9cf8c42bba5538, 0x215509a256e5e9ee, 0xc640032ab2f708b1, 0x310a7771b8410b2b,
0x6c88f05899e12448, 0x6637b2081fa382a2, 0x88691c8042a4f948, 0xfc1823cb9b7d0c6e, 0x20990a68393ae233,
0x99e282230d58ba51, 0xab43f34aa81839b9, 0x4acbe9dbdeab1878, 0x844388b26e8baf5e, 0x981efa94ee40ba21,
0x32e3b16564cd5a29, 0x39e08cb145bd1ec2, 0x9752701a92478262, 0x0a363cf3ae941b81, 0x30cd1f89a512ac02
```
