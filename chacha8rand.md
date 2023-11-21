# ChaCha8Rand

ChaCha8Rand is a ChaCha8-based key-erasure CSPRNG with performance similar to non-cryptographic random number generators, designed to be [the default source for the `math/rand{,v2}` and `runtime` Go packages](https://go.dev/issue/61716).

It accepts a 32-bytes seed, and requires 289 bytes of state, which can be serialized to 33 bytes (see below). It’s optimized for systems with 128-bit vector math. With larger states, it can be optimized further with 256- or 512-bit vector math.

If the ability to serialize the state to 33 bytes is desired, the output becomes unrecoverable (in terms of forward secrecy or backtrack resistance) after at most 992 bytes of additional output are drawn. If the ability to compress the state is not necessary, it can be operated in a regular fast-key-erasure fashion.

## Description

Each iteration of ChaCha8Rand operates over 32 bytes of input and produces 992 bytes of RNG output, plus 32 bytes of input for the next iteration.

The 32 bytes of input are used as a ChaCha8 key, with a zero nonce, to produce 1024 bytes of output (16 blocks, with counters 0 to 15). First, for each block, the values `0x61707865`, `0x3320646e`, `0x79622d32`, `0x6b206574` are subtracted from the 32-bit little-endian words at position 0, 1, 2, and 3 respectively, and an increasing counter starting at zero is subtracted from each word at position 12. Then, this stream is permuted such that for each sequence of four blocks, first we output the first four bytes of each block, then the next four bytes of each block, and so on. Finally, the last 32 bytes of output are used as the input of the next iteration, and the remaining 992 bytes are the RNG output.

```
stream = ChaCha8(key = input, nonce = {0}, len = 1024)
for (i = 0; i < 16; i++) // for each block
	stream[i*64 + 0*4 : i*64 + 0*4 + 4] -= 0x61707865
	stream[i*64 + 1*4 : i*64 + 1*4 + 4] -= 0x3320646e
	stream[i*64 + 2*4 : i*64 + 2*4 + 4] -= 0x79622d32
	stream[i*64 + 3*4 : i*64 + 3*4 + 4] -= 0x6b206574
	stream[i*64 + 12*4 : i*64 + 12*4 + 4] -= i
output = ""
for (b = 0; b < 16; n += 4) // for each sequence of four blocks
	for (i = 0; i < 64; i += 4) // for each four bytes in a block
		output += stream[0*64 + i : 0*64 + i + 4]
		output += stream[1*64 + i : 1*64 + i + 4]
		output += stream[2*64 + i : 2*64 + i + 4]
		output += stream[3*64 + i : 3*64 + i + 4]
	stream = stream[256:]
next_input = output[1024-32:]
output = output[:1024-32]
```

Note that the subtractions are equivalent to skipping the final state addition for the constant, nonce, and counter terms.

## Design rationale

**Why the permutation?** On platforms with SIMD registers that can hold 128 bits, ChaCha can be parallelized four-ways (that is, producing four blocks at a time) by packing the first uint32 of state for each block in the first SIMD register, and so on. Defining the output to be permuted like in ChaCha8Rand allows producing it without having to deinterlace it, by simply concatenating the packed SIMD registers.

**Why sixteen blocks at a time?** All amd64 processors have 128-bit vector registries, so we can target them without CPU feature detection. Other implementers might find it preferable to pay the complexity and buffer size cost to parallelize eight or sixteen blocks, with 256-bit and 512-bit vector instructions respectively. We produce sixteen blocks before rekeying but interlace four to optimize for a smaller buffer (of four block at a time) but still future-proof (by allowing up to sixteen blocks to be generated at a time with 512-bit vector instructions) and improve throughput.

**Key erasure vs state compression.** Traditional key erasure involves immediately overwriting the key, and deleting buffered output bytes as soon as they are produced. An alternative strategy is deferring the overwriting until the next iteration starts, in which case the state can be serialized to just the last iteration input (from which the current buffer and the next iteration key can be regenerated) and a counter.

**Why the subtractions?** ChaCha8 needs to adds the key back to the output, or the block function would be invertible. However, adding back the constants and the counter is unnecessary (as they are public), and is done maybe to allow adding the state as a whole when non-interlaced. (The security importance of adding back the key is mentioned in passing in the [XSalsa20 paper](https://cr.yp.to/snuffle/xsalsa-20110204.pdf), at page 5, when defining HSalsa20.) This is only slowing down SIMD implementations, so it is skipped.

**Why ChaCha8?** The goal was designing a CSPRNG fast enough that it could viably replace a non-cryptographic PRNG, so performance was a primary goal. [Too Much Crypto by Jean-Philippe Aumasson](https://eprint.iacr.org/2019/1492.pdf) provides a compelling rationale for why eight rounds are enough.

## Sample output

For the input `ABCDEFGHIJKLMNOPQRSTUVWXYZ123456` (in ASCII), this is the first 2976 bytes of ChaCha8Rand output, as produced by the program in the `chacha8rand` directory.

```
a516463d06b673b73cbc6aa622af60117c288d41d999258cd65cdc7e037ee07e
ad161c2de09eaacf79eaeb8fef0e090e3e5b8b1271d2823c4fa35212c1dd5a9c
a6ee6c7d61bb79df6a739d1f5953d5361fe01e184ed1f0ee3684e50a76fc9b08
68d22acc592be5d9ba8a1b4b44b42feb6166c492a6c8954f2ce6ca173232c6c3
7e2e4e7f36b4eb91c69beca0c6f24c7820beea345cec345ca8da7055518f0a4f
f26b3d11b4dc35fcbc5455644ca40d5be1d921dba33d966df300e55031fcaeee
a55037da3d92372db0c84b6d627a0d3849eed7e3ed68afee7c713b88956635f4
a495243921906a841ba630965410858e93e4ba5d5402dc18433d5aa6f09f8f0f
80f00f19f765f0cc30336739aad176fd3364ba6c9332d29517bd0c07d156746c
62658cffdacf2a466afc346d86abaf5b88290a03782f860c3d16c307e4839ad3
bf2ef2457b2b0ac0a9b16624c6074356d472c0b024047e25fe286c49995eb56f
e0d45c8fa87398ae73370dc62a3657468e3ef2cd1ef9831cc08753c19207dc6f
5c2bfd0da3d2da36b7bd95052993b5a4c502cce43489e14da7e315f004d6c0cd
2103d89af6dba0fb87de39d1a3bee8605687f41e854d8ad14af315227c446663
ee07d0d3972e6805b24ad5c678890e4cc2ed12676a9f1ecfd3cf804c41391406
ad0e5c74e2b6a8d1e810c4458d91a731ec6e2190ad61ccab1aa732202dd94040
68cd40fb6ff6d23c7a859572c051d0dc7e52abd9bc5cb5eaacda1b78ce1d4718
5272dc44d18cf0f7d1407f3db1e004585bd3b2e446a4b15c068a13d228a7d4e6
d8da60ca403e2205686aac0632ec612db8174c87562369ab1cde7676415409c3
2456223237ce1a4f388398130851a9fb112e75520f207f99fa2162e8afaa1611
1935a1b25c3bce07148345bc72bc562978eb406192b788414deaadd4bf6dca56
e50c344923c2e37f8a5f67379c8fc03521d55eeffbc7e11175bcc14e46c8ad98
f803123dc7b263d1f3f3a243e01e768cb7d7eccc6a9db92470032f11aa313e79
395128192adc878e256e09f704ae47420fe26f9222314f51e9a7d245f0b36fdc
ba8ed1cdce30cb15740290f6ecfdc7cb21a08bdc96c6b53fe674d2c8174466d1
787245ea45e4f70557b69d1bcabb20f999cb22dab450190c92e209aff1ba75f8
38f85042b8d7d3be6041d70f08e898f103a77e9b1da5edc9f6f89b4355ef09f7
fc16f1ebfe740cd246756d14eb6856308797d810ecf39a82bc1d557b69f9b815
c9b8648e6c3c82fcbc403b18e8855534681358d671414b67f7e970d61cd83412
195ea5d81052500edca0ecee698d25e87ef6bae852c4d4059955a41601e3dbe8
006f17b1e18cf01c49cb1eb8a4d0f7cc0e432c6b13ea3f3071c8069c136c1d86
87045ee072df415f1d6be21a1e7ebd251da462d604409fbe46851883d458bf65
cc13db69ff7cb2d136bbc1723366a6014d7f727b57d78d57f63c086c068fc719
bb91c3f9d414e0dbb3ff131dddb2fb974f8deff90a1ec931ba432a4098fc4d09
52b737ea1bd69b06ca86d9e862d7725b85bc04598631ee723ec336cdc5fdf5d1
ad7c94a880499bba43ab49ac5ef0e8ece738aeab8411fe655214d3a5deb97c2d
e367e476944871cc8cc678a558a2034cfcd80fcb9edfef006d66e271d4ca2499
e965f7188366f887d8f5551b7cc54dcb594860865a8373d382e440558b5626e5
ec6f58080f04391fe6f89302f0f364b7a850bdf6a24394041a94d39786c8fe76
a2e7ba39d070fb3ea8a8ec681361f4e225241de0967a007cbfc5698e76e5ccbb
c3aa425c98b44f78743822aa91502bf7072ee6b13f333036deb8bbdeeb19738e
00fa59a9bc82392ab3a94b969f8bb9b25119b7ad1410e3f782cc3a70a3fcd0eb
9a41e62f2a4e65ec2c2ea5552d1326b3782950447fc5482216af2d342f0c7132
ec2bcb5a7bb41705370927ca8f717a4c41c5bcd0be4291d688ce52ffb8bc0ee4
d428f8c9dba2443e583f878f4f2f4cc75be499b78e64bf3df8860eee7524f233
657fd416eef9b41ee3442771b8d2f8407245b13cdab486b84df6d6bd6f328620
b982d87d90e53dccdf09e95e9ab4e8a2104c9623788efbdbd5f80def8960dd70
9fc9d9cd631614306503245c3205b804d612ac1403d88374f9f5a71ab91c272b
f0ddab625324e297ab9f2a2314f6845aa27f4bdafc2511f76772b2741da6a51c
45cbdb3a9b6acc38393e65dc85bbe1ddd49ff864fac8d0e988412bcd1efbc502
e55657ca7b13bdf255e11b125de2efad8e3a895d3c1ccd56b95bb6be37d3504c
67f55c6751518c911e6ab5cfff49a6abcd47226ab24ac720da083c85ac6b1671
5dfc84e5e2ef7bb032bf8d582aff45da5e09754d3cb098db4c5aa6aae15a2860
b84031266a683bf90e181cee529746deae9a1204dc32c2ce04ea3518aa6b91eb
ff8843b6c8219cd488488658962da872a866ac7eef483300eb09b255e6676f7f
251b947a0bfb2f53deee8d12e6ad40d923fe89afa1f224dfe05a1988493baa95
4abe944f4049a63d277e3f2c13ad2d69b89eaaca6ee7ae40245065091ea09412
f5e4a4dbab97f76d32701d4c02b62feafc89542992044e5f6ae022ea14299757
73d4aa33d137819af3f2cde76adde6a2476608184f64429f3ebd70c10133d016
6d6546a56f418c903e122ee23b5081e072ccc41691f07c0729f2b764d25cd2cb
314059ec68f4b23dd5ad9b4c730ec04661d87520c70aecd030760bf83ccb3730
c621273a7b3d4c574b8276006a9099ae702e538b41a575b1dd1d23ee51e2b3d8
6619ca5dc2ee33b4939aff5cdc300f5335d33cb5983df09fdf8c55765022c4af
2a408482a2d381ef280a111cf5db0b11f6e827d055b2e19a32836824aae0e37d
e27e06d2ecc383e4e63761278b3229f8ad2c5657adcc13a41fcb6a498b8e11e6
1fc05edaa6dc88825572c188dc7737a5da6e71d5e0f1008aa820a7b7476f8e61
41a892c6b007399ef3343f96ca428b97efd7a798cdb0e47552475f0b6ebd4dde
3f49343f15e45202f94e7303d8e7f050ee67d18ea3667723a039ee0140412441
21bb35e543f68dd0740ba8a9b575f53455f79772f83a342ccbf721d8996d8bcd
ae48fc5672fd76e385283534736eb0e1eb69c1866fb287fade71a9654660c136
808e9c23c247a1db240e7ffc698e206bc3602b6f5b399587f4074919e9beda05
02d95e2f147581b981dc1d02e201175e08ed5e75a2ab750895de519228838d77
31cb9e036ae4fb3bf9d7cbe4fc0447b23d1ec9a7e9ff8569bbda49f23db1efc8
f6c9f4b0647e03b1c3b7d697d19ff6550ca9681dd78925677ea7504f22b8bdbe
a7747300809f583f2a18545963f407d390fdd4100c85f5cf158e40b6df02dac6
85a4b1e2f1eeda9325a6ee8a2033d865fab5d33ea13fb1e28eb60f1338350567
a98f2198652f04c12e8a9b74caad5bee7de3da47f9a3226dafdbf457166d2cb6
0bc20497e67d006ed84138fc13b9f21a228e2e8e34470edc228b95cff1de1d9b
b8663023b0d62e63f2d8be11332dd0dde9564683e1cf47f17a5911d549aa9a39
0903ec796988146b97fb5a6bc34afc6481f07c7fe0782fb81b0e3d329a5c9210
f6633ce19ec751f4c776783180c12f7c227dcbeed92ba135901f6239a5545633
f081b55df3a332cccb69230ba84807c66b159185b0d34d7c9122e26d4bed1cac
f5de34f12dfa2ca3532aea8d91087162f44fcb8f60b155053ca3aa43ace73e14
18c24fcfe70ce9dab5f4bc8225fc684d715d1349184e0937d89fd4f3097e85f7
e78b7603c538750001e66b2fba48f6ed3e5172dd647634aa863bf26e3c8963be
97af050671850b1356abf61e6b5c76dd6bdc979a629a24f3e5b8fa20904f112a
08adc6cf27e0695a50e0a5f136cb4c3ca5f03468597d9e2e89e7fc5868be3024
97e566242f860be9eca959f184285e8957cb2f90a48fab2650fae1545cffefa6
55821a81e5c43a33118649025f518da5f46e5cb2dc095afe18585fab88898903
17c6f62a24f69f2823ea81d39fd59d3d51ae8a8a3dd9d7526f781f513d126ac7
6cc400afed0189f680de90b57108638c91e09189309c2005778178b4999f801f
d89fc1b62e0c171158ba6290773c4344454c87f11ab5acc0a19f808442132e9f
fa19c615bd23b5edc023cc3ed57fd9024c376244a305afac1fa1ff4bd3c6d9dd
```

This is the same output interpreted as a sequence of little-endian uint64s.

```
0xb773b6063d4616a5, 0x1160af22a66abc3c, 0x8c2599d9418d287c, 0x7ee07e037edc5cd6,
0xcfaa9ee02d1c16ad, 0x0e090eef8febea79, 0x3c82d271128b5b3e, 0x9c5addc11252a34f,
0xdf79bb617d6ceea6, 0x36d553591f9d736a, 0xeef0d14e181ee01f, 0x089bfc760ae58436,
0xd9e52b59cc2ad268, 0xeb2fb4444b1b8aba, 0x4f95c8a692c46661, 0xc3c6323217cae62c,
0x91ebb4367f4e2e7e, 0x784cf2c6a0ec9bc6, 0x5c34ec5c34eabe20, 0x4f0a8f515570daa8,
0xfc35dcb4113d6bf2, 0x5b0da44c645554bc, 0x6d963da3db21d9e1, 0xeeaefc3150e500f3,
0x2d37923dda3750a5, 0x380d7a626d4bc8b0, 0xeeaf68ede3d7ee49, 0xf4356695883b717c,
0x846a9021392495a4, 0x8e8510549630a61b, 0x18dc02545dbae493, 0x0f8f9ff0a65a3d43,
0xccf065f7190ff080, 0xfd76d1aa39673330, 0x95d232936cba6433, 0x6c7456d1070cbd17,
0x462acfdaff8c6562, 0x5bafab866d34fc6a, 0x0c862f78030a2988, 0xd39a83e407c3163d,
0xc00a2b7b45f22ebf, 0x564307c62466b1a9, 0x257e0424b0c072d4, 0x6fb55e99496c28fe,
0xae9873a88f5cd4e0, 0x4657362ac60d3773, 0x1c83f91ecdf23e8e, 0x6fdc0792c15387c0,
0x36dad2a30dfd2b5c, 0xa4b593290595bdb7, 0x4de18934e4cc02c5, 0xcdc0d604f015e3a7,
0xfba0dbf69ad80321, 0x60e8bea3d139de87, 0xd18a4d851ef48756, 0x6366447c2215f34a,
0x05682e97d3d007ee, 0x4c0e8978c6d54ab2, 0xcf1e9f6a6712edc2, 0x061439414c80cfd3,
0xd1a8b6e2745c0ead, 0x31a7918d45c410e8, 0xabcc61ad90216eec, 0x4040d92d2032a71a,
0x3cd2f66ffb40cd68, 0xdcd051c07295857a, 0xeab55cbcd9ab527e, 0x18471dce781bdaac,
0xf7f08cd144dc7252, 0x5804e0b13d7f40d1, 0x5cb1a446e4b2d35b, 0xe6d4a728d2138a06,
0x05223e40ca60dad8, 0x2d61ec3206ac6a68, 0xab692356874c17b8, 0xc30954417676de1c,
0x4f1ace3732225624, 0xfba9510813988338, 0x997f200f52752e11, 0x1116aaafe86221fa,
0x07ce3b5cb2a13519, 0x2956bc72bc458314, 0x4188b7926140eb78, 0x56ca6dbfd4adea4d,
0x7fe3c22349340ce5, 0x35c08f9c37675f8a, 0x11e1c7fbef5ed521, 0x98adc8464ec1bc75,
0xd163b2c73d1203f8, 0x8c761ee043a2f3f3, 0x24b99d6accecd7b7, 0x793e31aa112f0370,
0x8e87dc2a19285139, 0x4247ae04f7096e25, 0x514f3122926fe20f, 0xdc6fb3f045d2a7e9,
0x15cb30cecdd18eba, 0xcbc7fdecf6900274, 0x3fb5c696dc8ba021, 0xd1664417c8d274e6,
0x05f7e445ea457278, 0xf920bbca1b9db657, 0x0c1950b4da22cb99, 0xf875baf1af09e292,
0xbed3d7b84250f838, 0xf198e8080fd74160, 0xc9eda51d9b7ea703, 0xf709ef55439bf8f6,
0xd20c74feebf116fc, 0x305668eb146d7546, 0x829af3ec10d89787, 0x15b8f9697b551dbc,
0xfc823c6c8e64b8c9, 0x345585e8183b40bc, 0x674b4171d6581368, 0x1234d81cd670e9f7,
0x0e505210d8a55e19, 0xe8258d69eeeca0dc, 0x05d4c452e8baf67e, 0xe8dbe30116a45599,
0x1cf08ce1b1176f00, 0xccf7d0a4b81ecb49, 0x303fea136b2c430e, 0x861d6c139c06c871,
0x5f41df72e05e0487, 0x25bd7e1e1ae26b1d, 0xbe9f4004d662a41d, 0x65bf58d483188546,
0xd1b27cff69db13cc, 0x01a6663372c1bb36, 0x578dd7577b727f4d, 0x19c78f066c083cf6,
0xdbe014d4f9c391bb, 0x97fbb2dd1d13ffb3, 0x31c91e0af9ef8d4f, 0x094dfc98402a43ba,
0x069bd61bea37b752, 0x5b72d762e8d986ca, 0x72ee31865904bc85, 0xd1f5fdc5cd36c33e,
0xba9b4980a8947cad, 0xece8f05eac49ab43, 0x65fe1184abae38e7, 0x2d7cb9dea5d31452,
0xcc71489476e467e3, 0x4c03a258a578c68c, 0x00efdf9ecb0fd8fc, 0x9924cad471e2666d,
0x87f8668318f765e9, 0xcb4dc57c1b55f5d8, 0xd373835a86604859, 0xe526568b5540e482,
0x1f39040f08586fec, 0xb764f3f00293f8e6, 0x049443a2f6bd50a8, 0x76fec88697d3941a,
0x3efb70d039bae7a2, 0xe2f4611368eca8a8, 0x7c007a96e01d2425, 0xbbcce5768e69c5bf,
0x784fb4985c42aac3, 0xf72b5091aa223874, 0x3630333fb1e62e07, 0x8e7319ebdebbb8de,
0x2a3982bca959fa00, 0xb2b98b9f964ba9b3, 0xf7e31014adb71951, 0xebd0fca3703acc82,
0xec654e2a2fe6419a, 0xb326132d55a52e2c, 0x2248c57f44502978, 0x32710c2f342daf16,
0x0517b47b5acb2bec, 0x4c7a718fca270937, 0xd69142bed0bcc541, 0xe40ebcb8ff52ce88,
0x3e44a2dbc9f828d4, 0xc74c2f4f8f873f58, 0x3dbf648eb799e45b, 0x33f22475ee0e86f8,
0x1eb4f9ee16d47f65, 0x40f8d2b8712744e3, 0xb886b4da3cb14572, 0x2086326fbdd6f64d,
0xcc3de5907dd882b9, 0xa2e8b49a5ee909df, 0xdbfb8e7823964c10, 0x70dd6089ef0df8d5,
0x30141663cdd9c99f, 0x04b805325c240365, 0x7483d80314ac12d6, 0x2b271cb91aa7f5f9,
0x97e2245362abddf0, 0x5a84f614232a9fab, 0xf71125fcda4b7fa2, 0x1ca5a61d74b27267,
0x38cc6a9b3adbcb45, 0xdde1bb85dc653e39, 0xe9d0c8fa64f89fd4, 0x02c5fb1ecd2b4188,
0xf2bd137bca5756e5, 0xadefe25d121be155, 0x56cd1c3c5d893a8e, 0x4c50d337beb65bb9,
0x918c5151675cf567, 0xaba649ffcfb56a1e, 0x20c74ab26a2247cd, 0x71166bac853c08da,
0xb07befe2e584fc5d, 0xda45ff2a588dbf32, 0xdb98b03c4d75095e, 0x60285ae1aaa65a4c,
0xf93b686a263140b8, 0xde469752ee1c180e, 0xcec232dc04129aae, 0xeb916baa1835ea04,
0xd49c21c8b64388ff, 0x72a82d9658864888, 0x003348ef7eac66a8, 0x7f6f67e655b209eb,
0x532ffb0b7a941b25, 0xd940ade6128deede, 0xdf24f2a1af89fe23, 0x95aa3b4988195ae0,
0x3da649404f94be4a, 0x692dad132c3f7e27, 0x40aee76ecaaa9eb8, 0x1294a01e09655024,
0x6df797abdba4e4f5, 0xea2fb6024c1d7032, 0x5f4e0492295489fc, 0x57972914ea22e06a,
0x9a8137d133aad473, 0xa2e6dd6ae7cdf2f3, 0x9f42644f18086647, 0x16d03301c170bd3e,
0x908c416fa546656d, 0xe081503be22e123e, 0x077cf09116c4cc72, 0xcbd25cd264b7f229,
0x3db2f468ec594031, 0x46c00e734c9badd5, 0xd0ec0ac72075d861, 0x3037cb3cf80b7630,
0x574c3d7b3a2721c6, 0xae99906a0076824b, 0xb175a5418b532e70, 0xd8b3e251ee231ddd,
0xb433eec25dca1966, 0x530f30dc5cff9a93, 0x9ff03d98b53cd335, 0xafc4225076558cdf,
0xef81d3a28284402a, 0x110bdbf51c110a28, 0x9ae1b255d027e8f6, 0x7de3e0aa24688332,
0xe483c3ecd2067ee2, 0xf829328b276137e6, 0xa413ccad57562cad, 0xe6118e8b496acb1f,
0x8288dca6da5ec01f, 0xa53777dc88c17255, 0x8a00f1e0d5716eda, 0x618e6f47b7a720a8,
0x9e3907b0c692a841, 0x978b42ca963f34f3, 0x75e4b0cd98a7d7ef, 0xde4dbd6e0b5f4752,
0x0252e4153f34493f, 0x50f0e7d803734ef9, 0x237766a38ed167ee, 0x4124414001ee39a0,
0xd08df643e535bb21, 0x34f575b5a9a80b74, 0x2c343af87297f755, 0xcd8b6d99d821f7cb,
0xe376fd7256fc48ae, 0xe1b06e7334352885, 0xfa87b26f86c169eb, 0x36c1604665a971de,
0xdba147c2239c8e80, 0x6b208e69fc7f0e24, 0x8795395b6f2b60c3, 0x05dabee9194907f4,
0xb98175142f5ed902, 0x5e1701e2021ddc81, 0x0875aba2755eed08, 0x778d83289251de95,
0x3bfbe46a039ecb31, 0xb24704fce4cbd7f9, 0x6985ffe9a7c91e3d, 0xc8efb13df249dabb,
0xb1037e64b0f4c9f6, 0x55f69fd197d6b7c3, 0x672589d71d68a90c, 0xbebdb8224f50a77e,
0x3f589f80007374a7, 0xd307f4635954182a, 0xcff5850c10d4fd90, 0xc6da02dfb6408e15,
0x93daeef1e2b1a485, 0x65d833208aeea625, 0xe2b13fa13ed3b5fa, 0x67053538130fb68e,
0xc1042f6598218fa9, 0xee5badca749b8a2e, 0x6d22a3f947dae37d, 0xb62c6d1657f4dbaf,
0x6e007de69704c20b, 0x1af2b913fc3841d8, 0xdc0e47348e2e8e22, 0x9b1ddef1cf958b22,
0x632ed6b0233066b8, 0xddd02d3311bed8f2, 0xf147cfe1834656e9, 0x399aaa49d511597a,
0x6b14886979ec0309, 0x64fc4ac36b5afb97, 0xb82f78e07f7cf081, 0x10925c9a323d0e1b,
0xf451c79ee13c63f6, 0x7c2fc180317876c7, 0x35a12bd9eecb7d22, 0x335654a539621f90,
0xcc32a3f35db581f0, 0xc60748a80b2369cb, 0x7c4dd3b08591156b, 0xac1ced4b6de22291,
0xa32cfa2df134def5, 0x627108918dea2a53, 0x0555b1608fcb4ff4, 0x143ee7ac43aaa33c,
0xdae90ce7cf4fc218, 0x4d68fc2582bcf4b5, 0x37094e1849135d71, 0xf7857e09f3d49fd8,
0x007538c503768be7, 0xedf648ba2f6be601, 0xaa347664dd72513e, 0xbe63893c6ef23b86,
0x130b85710605af97, 0xdd765c6b1ef6ab56, 0xf3249a629a97dc6b, 0x2a114f9020fab8e5,
0x5a69e027cfc6ad08, 0x3c4ccb36f1a5e050, 0x2e9e7d596834f0a5, 0x2430be6858fce789,
0xe90b862f2466e597, 0x895e2884f159a9ec, 0x26ab8fa4902fcb57, 0xa6efff5c54e1fa50,
0x333ac4e5811a8255, 0xa58d515f02498611, 0xfe5a09dcb25c6ef4, 0x03898988ab5f5818,
0x289ff6242af6c617, 0x3d9dd59fd381ea23, 0x52d7d93d8a8aae51, 0xc76a123d511f786f,
0xf68901edaf00c46c, 0x8c630871b590de80, 0x05209c308991e091, 0x1f809f99b4788177,
0x11170c2eb6c19fd8, 0x44433c779062ba58, 0xc0acb51af1874c45, 0x9f2e134284809fa1,
0xedb523bd15c619fa, 0x02d97fd53ecc23c0, 0xacaf05a34462374c, 0xddd9c6d34bffa11f
```
