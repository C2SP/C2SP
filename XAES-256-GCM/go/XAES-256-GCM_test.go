package xaes256gcm_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	"xaes256gcm"

	"golang.org/x/crypto/sha3"
)

func TestVectors(t *testing.T) {
	key := bytes.Repeat([]byte{0x01}, xaes256gcm.KeySize)
	nonce := []byte("ABCDEFGHIJKLMNOPQRSTUVWX")
	plaintext := []byte("XAES-256-GCM")
	c, err := xaes256gcm.New(key)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext := c.Seal(nil, nonce, plaintext, nil)
	expected := "ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e2271"
	if got := hex.EncodeToString(ciphertext); got != expected {
		t.Errorf("got: %s", got)
	}
	if decrypted, err := c.Open(nil, nonce, ciphertext, nil); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("plaintext and decrypted are not equal")
	}

	key = bytes.Repeat([]byte{0x03}, xaes256gcm.KeySize)
	aad := []byte("c2sp.org/XAES-256-GCM")
	c, err = xaes256gcm.New(key)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext = c.Seal(nil, nonce, plaintext, aad)
	expected = "986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d"
	if got := hex.EncodeToString(ciphertext); got != expected {
		t.Errorf("got: %s", got)
	}
	if decrypted, err := c.Open(nil, nonce, ciphertext, aad); err != nil {
		t.Fatal(err)
	} else if !bytes.Equal(plaintext, decrypted) {
		t.Errorf("plaintext and decrypted are not equal")
	}
}

func TestAccumulated(t *testing.T) {
	iterations := 10_000
	expected := "e6b9edf2df6cec60c8cbd864e2211b597fb69a529160cd040d56c0c210081939"
	if !testing.Short() {
		iterations = 1_000_000
		expected = "2163ae1445985a30b60585ee67daa55674df06901b890593e824b8a7c885ab15"
	}

	s, d := sha3.NewShake128(), sha3.NewShake128()
	for i := 0; i < iterations; i++ {
		key := make([]byte, xaes256gcm.KeySize)
		s.Read(key)
		nonce := make([]byte, xaes256gcm.NonceSize)
		s.Read(nonce)
		lenByte := make([]byte, 1)
		s.Read(lenByte)
		plaintext := make([]byte, int(lenByte[0]))
		s.Read(plaintext)
		s.Read(lenByte)
		aad := make([]byte, int(lenByte[0]))
		s.Read(aad)

		c, err := xaes256gcm.New(key)
		if err != nil {
			t.Fatal(err)
		}
		ciphertext := c.Seal(nil, nonce, plaintext, aad)
		decrypted, err := c.Open(nil, nonce, ciphertext, aad)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("plaintext and decrypted are not equal")
		}

		d.Write(ciphertext)
	}
	if got := hex.EncodeToString(d.Sum(nil)); got != expected {
		t.Errorf("got: %s", got)
	}
}
