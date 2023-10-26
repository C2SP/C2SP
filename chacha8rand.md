# ChaCha8Rand

ChaCha8Rand is a ChaCha8-based key-erasure CSPRNG with performance similar to non-cryptographic random number generators, designed to be [the default source for the `math/rand{,v2}` and `runtime` Go packages](https://go.dev/issue/61716).

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
ea8cad7447fe45bf44c1fcb171e200b2df437ea612cc0c49ab174e09213c6b87b2c0ab7de537a3a7
c308737d35437b07a6ee6c7d61bb79df6a739d1f5953d5361fe01e184ed1f0ee3684e50a76fc9b08
68d22acc592be5d9ba8a1b4b44b42feb6166c492a6c8954f2ce6ca173232c6c37e2e4e7f36b4eb91
c69beca0c6f24c7820beea345cec345ca8da7055518f0a4ff26b3d11b4dc35fcbc5455644ca40d5b
e1d921dba33d966df300e55031fcaeeea55037da3e92372db2c84b6d657a0d3849eed7e3ed68afee
7c713b88956635f4a495243921906a841ba630965410858e93e4ba5d5402dc18433d5aa6f09f8f0f
451189f51ca6888866011d42fe14d363686c20e964b5fbe4685bcaa25f5ee144bceaec202e6803ef
7710d8dd3dbaaafe4b8e7fb42e8aa49baa67987e23c35d5036cb7e1d940890018b9507444adfe2cf
e8d87e0f9991ff6675afe723a9a7133361fca714a28d99b0b292b61cddd7a20b9915fb650592c58d
005e0310c4abd82707834cd00d16142aa1f9fecedaddca2c3d66cef8af1b9ac49c7c5b8963011408
c17eea82507542c01830ab20faa0475a2f4d20d1e087bdf1692377a07071d9db7a683bfc46f5e766
1423fe84eda633dca642c15acb258a5960a5d0bc2f5d3d18132de63bdbd310aacf78a8eff082eb89
bec8741ee0df78c8a63346e156966d7ded0b815ab8da67cff252808fed18ea510bc923873fca7f41
9e2f478caec918c31f3783628c4276dd1163a53ed5158887a01946d5796771255704721ec5c63b55
9366a6d8cb64149ddfb4417f7c13d13b0519d479b3ec2b89bad49cbd162bf05470f5d71d9d1ce405
9df442acff9869c4827af581c8fd8aa114b9b895fcd8ea5e8e0a1b926d9f0307ae1f9ce6b8c7dea6
f18d5ba23131984630de98b3c35fa7002f026db7f1826700baa04329b5c4a2eb997e272a0728fd5e
c69e375377edbf5d7847a9ba41638335fd229d97f3c358b2ff36c58eea7f95c806775a4e8ccc121d
```

This is the same output interpreted as a sequence of little-endian uint64s.

```
0xbf45fe4774ad8cea, 0xb200e271b1fcc144, 0x490ccc12a67e43df, 0x876b3c21094e17ab, 0xa7a337e57dabc0b2,
0x077b43357d7308c3, 0xdf79bb617d6ceea6, 0x36d553591f9d736a, 0xeef0d14e181ee01f, 0x089bfc760ae58436,
0xd9e52b59cc2ad268, 0xeb2fb4444b1b8aba, 0x4f95c8a692c46661, 0xc3c6323217cae62c, 0x91ebb4367f4e2e7e,
0x784cf2c6a0ec9bc6, 0x5c34ec5c34eabe20, 0x4f0a8f515570daa8, 0xfc35dcb4113d6bf2, 0x5b0da44c645554bc,
0x6d963da3db21d9e1, 0xeeaefc3150e500f3, 0x2d37923eda3750a5, 0x380d7a656d4bc8b2, 0xeeaf68ede3d7ee49,
0xf4356695883b717c, 0x846a9021392495a4, 0x8e8510549630a61b, 0x18dc02545dbae493, 0x0f8f9ff0a65a3d43,
0x8888a61cf5891145, 0x63d314fe421d0166, 0xe4fbb564e9206c68, 0x44e15e5fa2ca5b68, 0xef03682e20eceabc,
0xfeaaba3dddd81077, 0x9ba48a2eb47f8e4b, 0x505dc3237e9867aa, 0x019008941d7ecb36, 0xcfe2df4a4407958b,
0x66ff91990f7ed8e8, 0x3313a7a923e7af75, 0xb0998da214a7fc61, 0x0ba2d7dd1cb692b2, 0x8dc5920565fb1599,
0x27d8abc410035e00, 0x2a14160dd04c8307, 0x2ccadddacefef9a1, 0xc49a1baff8ce663d, 0x08140163895b7c9c,
0xc042755082ea7ec1, 0x5a47a0fa20ab3018, 0xf1bd87e0d1204d2f, 0xdbd97170a0772369, 0x66e7f546fc3b687a,
0xdc33a6ed84fe2314, 0x598a25cb5ac142a6, 0x183d5d2fbcd0a560, 0xaa10d3db3be62d13, 0x89eb82f0efa878cf,
0xc878dfe01e74c8be, 0x7d6d9656e14633a6, 0xcf67dab85a810bed, 0x51ea18ed8f8052f2, 0x417fca3f8723c90b,
0xc318c9ae8c472f9e, 0xdd76428c6283371f, 0x878815d53ea56311, 0x25716779d54619a0, 0x553bc6c51e720457,
0x9d1464cbd8a66693, 0x3bd1137c7f41b4df, 0x892becb379d41905, 0x54f02b16bd9cd4ba, 0x05e41c9d1dd7f570,
0xc46998ffac42f49d, 0xa18afdc881f57a82, 0x5eead8fc95b8b914, 0x07039f6d921b0a8e, 0xa6dec7b8e69c1fae,
0x46983131a25b8df1, 0x00a75fc3b398de30, 0x006782f1b76d022f, 0xeba2c4b52943a0ba, 0x5efd28072a277e99,
0x5dbfed7753379ec6, 0x35836341baa94778, 0xb258c3f3979d22fd, 0xc8957fea8ec536ff, 0x1d12cc8c4e5a7706
```
