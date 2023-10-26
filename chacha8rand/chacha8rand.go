// Copyright 2016 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"encoding/binary"
	"fmt"
	"math/bits"
)

func main() {
	input := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456")
	var uints []uint64
	for i := 0; i < 3; i++ {
		var output []byte
		stream := make([]byte, 256)
		ChaCha8(input, stream)
		for i := 0; i < 16; i++ {
			output = append(output, stream[i*4:i*4+4]...)
			output = append(output, stream[64+i*4:64+i*4+4]...)
			output = append(output, stream[128+i*4:128+i*4+4]...)
			output = append(output, stream[192+i*4:192+i*4+4]...)
		}
		copy(input, output[:16])
		output = output[16:]
		for i := 0; i < len(output); i += 8 {
			uints = append(uints, binary.LittleEndian.Uint64(output[i:]))
		}
		for len(output) > 0 {
			fmt.Printf("%x\n", output[:40])
			output = output[40:]
		}
	}
	fmt.Printf("%#x\n", uints)
}

func ChaCha8(key, dst []byte) {
	k := [8]uint32{
		binary.LittleEndian.Uint32(key[0:4]),
		binary.LittleEndian.Uint32(key[4:8]),
		binary.LittleEndian.Uint32(key[8:12]),
		binary.LittleEndian.Uint32(key[12:16]),
		binary.LittleEndian.Uint32(key[16:20]),
		binary.LittleEndian.Uint32(key[20:24]),
		binary.LittleEndian.Uint32(key[24:28]),
		binary.LittleEndian.Uint32(key[28:32]),
	}

	// To generate each block of key stream, the initial cipher state
	// (represented below) is passed through 8 rounds of shuffling,
	// alternatively applying quarterRounds by columns (like 1, 5, 9, 13)
	// or by diagonals (like 1, 6, 11, 12).
	//
	//      0:cccccccc   1:cccccccc   2:cccccccc   3:cccccccc
	//      4:kkkkkkkk   5:kkkkkkkk   6:kkkkkkkk   7:kkkkkkkk
	//      8:kkkkkkkk   9:kkkkkkkk  10:kkkkkkkk  11:kkkkkkkk
	//     12:bbbbbbbb  13:nnnnnnnn  14:nnnnnnnn  15:nnnnnnnn
	//
	//            c=constant k=key b=blockcount n=nonce
	var (
		c0, c1, c2, c3     = j0, j1, j2, j3
		c4, c5, c6, c7     = k[0], k[1], k[2], k[3]
		c8, c9, c10, c11   = k[4], k[5], k[6], k[7]
		c12, c13, c14, c15 = uint32(0), uint32(0), uint32(0), uint32(0)
	)

	// Three quarters of the first round don't depend on the counter, so we can
	// calculate them here, and reuse them for multiple blocks in the loop.
	p1, p5, p9, p13 := quarterRound(c1, c5, c9, c13)
	p2, p6, p10, p14 := quarterRound(c2, c6, c10, c14)
	p3, p7, p11, p15 := quarterRound(c3, c7, c11, c15)

	for len(dst) >= 64 {
		// The remainder of the first column round.
		fcr0, fcr4, fcr8, fcr12 := quarterRound(c0, c4, c8, c12)

		// The second diagonal round.
		x0, x5, x10, x15 := quarterRound(fcr0, p5, p10, p15)
		x1, x6, x11, x12 := quarterRound(p1, p6, p11, fcr12)
		x2, x7, x8, x13 := quarterRound(p2, p7, fcr8, p13)
		x3, x4, x9, x14 := quarterRound(p3, fcr4, p9, p14)

		// The remaining 18 rounds.
		for i := 0; i < 9; i++ {
			// Column round.
			x0, x4, x8, x12 = quarterRound(x0, x4, x8, x12)
			x1, x5, x9, x13 = quarterRound(x1, x5, x9, x13)
			x2, x6, x10, x14 = quarterRound(x2, x6, x10, x14)
			x3, x7, x11, x15 = quarterRound(x3, x7, x11, x15)

			// Diagonal round.
			x0, x5, x10, x15 = quarterRound(x0, x5, x10, x15)
			x1, x6, x11, x12 = quarterRound(x1, x6, x11, x12)
			x2, x7, x8, x13 = quarterRound(x2, x7, x8, x13)
			x3, x4, x9, x14 = quarterRound(x3, x4, x9, x14)
		}

		// Add back the initial state to generate the key stream.
		binary.LittleEndian.PutUint32(dst[0:4], x0+c0)
		binary.LittleEndian.PutUint32(dst[4:8], x1+c1)
		binary.LittleEndian.PutUint32(dst[8:12], x2+c2)
		binary.LittleEndian.PutUint32(dst[12:16], x3+c3)
		binary.LittleEndian.PutUint32(dst[16:20], x4+c4)
		binary.LittleEndian.PutUint32(dst[20:24], x5+c5)
		binary.LittleEndian.PutUint32(dst[24:28], x6+c6)
		binary.LittleEndian.PutUint32(dst[28:32], x7+c7)
		binary.LittleEndian.PutUint32(dst[32:36], x8+c8)
		binary.LittleEndian.PutUint32(dst[36:40], x9+c9)
		binary.LittleEndian.PutUint32(dst[40:44], x10+c10)
		binary.LittleEndian.PutUint32(dst[44:48], x11+c11)
		binary.LittleEndian.PutUint32(dst[48:52], x12+c12)
		binary.LittleEndian.PutUint32(dst[52:56], x13+c13)
		binary.LittleEndian.PutUint32(dst[56:60], x14+c14)
		binary.LittleEndian.PutUint32(dst[60:64], x15+c15)

		c12 += 1

		dst = dst[64:]
	}
}

// The constant first 4 words of the ChaCha20 state.
const (
	j0 uint32 = 0x61707865 // expa
	j1 uint32 = 0x3320646e // nd 3
	j2 uint32 = 0x79622d32 // 2-by
	j3 uint32 = 0x6b206574 // te k
)

// quarterRound is the core of ChaCha20. It shuffles the bits of 4 state words.
// It's executed 4 times for each of the 20 ChaCha20 rounds, operating on all 16
// words each round, in columnar or diagonal groups of 4 at a time.
func quarterRound(a, b, c, d uint32) (uint32, uint32, uint32, uint32) {
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 16)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 12)
	a += b
	d ^= a
	d = bits.RotateLeft32(d, 8)
	c += d
	b ^= c
	b = bits.RotateLeft32(b, 7)
	return a, b, c, d
}
