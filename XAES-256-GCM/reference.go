package xaes256gcm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

const (
	KeySize   = 32
	NonceSize = 24
	Overhead  = 16
)

type xaes256gcm struct {
	c  cipher.Block
	k1 [aes.BlockSize]byte
}

func New(key []byte) (cipher.AEAD, error) {
	if len(key) != KeySize {
		return nil, errors.New("xaes256gcm: bad key length")
	}

	x := new(xaes256gcm)

	x.c, _ = aes.NewCipher(key)
	x.c.Encrypt(x.k1[:], x.k1[:])

	var msb byte
	for i := len(x.k1) - 1; i >= 0; i-- {
		msb = x.k1[i] >> 7
		x.k1[i] = x.k1[i]<<1 | msb
	}
	x.k1[len(x.k1)-1] ^= msb * 0b10000111

	return x, nil
}

func (*xaes256gcm) NonceSize() int {
	return NonceSize
}

func (*xaes256gcm) Overhead() int {
	return Overhead
}

func (x *xaes256gcm) deriveKey(nonce []byte) []byte {
	k := make([]byte, 0, 2*aes.BlockSize)
	k = append(k, 0, 1, 'X', 0)
	k = append(k, nonce...)
	k = append(k, 0, 2, 'X', 0)
	k = append(k, nonce...)
	subtle.XORBytes(k[:aes.BlockSize], k[:aes.BlockSize], x.k1[:])
	subtle.XORBytes(k[aes.BlockSize:], k[aes.BlockSize:], x.k1[:])
	x.c.Encrypt(k[:aes.BlockSize], k[:aes.BlockSize])
	x.c.Encrypt(k[aes.BlockSize:], k[aes.BlockSize:])
	return k
}

func (x *xaes256gcm) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != NonceSize {
		panic("xaes256gcm: bad nonce length passed to Seal")
	}

	k, n := x.deriveKey(nonce[:12]), nonce[12:]
	c, _ := aes.NewCipher(k)
	a, _ := cipher.NewGCM(c)
	return a.Seal(dst, n, plaintext, additionalData)
}

var errOpen = errors.New("xaes256gcm: message authentication failed")

func (x *xaes256gcm) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != NonceSize {
		panic("xaes256gcm: bad nonce length passed to Open")
	}

	k, n := x.deriveKey(nonce[:12]), nonce[12:]
	c, _ := aes.NewCipher(k)
	a, _ := cipher.NewGCM(c)
	return a.Open(dst, n, ciphertext, additionalData)
}
