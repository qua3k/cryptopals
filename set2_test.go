// set2_test.go provides the actual challenges to solve

package cryptopals

import (
	"bytes"
	"crypto/aes"
	"os"
	"testing"
)

func TestChallenge9(t *testing.T) {
	key := []byte("YELLOW SUBMARINE")

	// expected values
	assert(t, "YELLOW SUBMARINE\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10", string(PadPKCS7(key, 16)))
	assert(t, "YELLOW SUBMARINE\x04\x04\x04\x04", string(PadPKCS7(key, 20)))
}

func TestChallenge10(t *testing.T) {
	const filename = "testdata/10.txt"

	bl, _ := aes.NewCipher([]byte("YELLOW SUBMARINE"))

	b, err := os.ReadFile(filename)
	if err != nil {
		t.Errorf("opening file %s failed with error %v\n", filename, err)
	}

	iv := make([]byte, bl.BlockSize())
	t.Log(string(DecryptCBC(bl, decodeBase64(b), iv)))
}

func TestChallenge11(t *testing.T) {
	oracle := NewCBCECBOracle()

	var ecb, cbc int
	for i := 0; i < 1000; i++ {
		b := oracle(bytes.Repeat([]byte{'A'}, 16*3))
		if DetectECB(b, 16) {
			ecb++
			continue
		}
		cbc++
	}
	t.Log(ecb, "ciphertexts were encrypted in ECB mode")
	t.Log(cbc, "ciphertexts were encrypted in CBC mode")
}

func TestChallenge12(t *testing.T) {

	oracle := NewAppendECBOracle("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

	d := DecryptAppendOracle(oracle)
	t.Log(string(d))
}

func TestChallenge13(t *testing.T) {
	oracle, bl := NewProfileOracle()
	c := GenerateAdmin(oracle, bl.BlockSize())

	if !DecryptAdmin(c, bl) {
		t.Error("expected to gain admin access...")
	}
}

func TestChallenge14(t *testing.T) {

	oracle := NewPrependECBOracle("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")

	d := DecryptPrependOracle(oracle)
	t.Log(string(d))
}

func TestChallenge15(t *testing.T) {
	const (
		x = "ICE ICE BABY\x04\x04\x04\x04"
		y = "ICE ICE BABY\x05\x05\x05\x05"
		z = "ICE ICE BABY\x01\x02\x03\x04"

		i = "ICE ICE BABY"
	)

	assert(t, string(UnpadPKCS7([]byte(x), 16)), i)
	if r := UnpadPKCS7([]byte(y), 16); r != nil {
		t.Error("should have gotten incorrect padding, instead got", r)
	}
	if r := UnpadPKCS7([]byte(z), 16); r != nil {
		t.Error("should have gotten incorrect padding, instead got", r)
	}

}

func TestChallenge16(t *testing.T) {
	oracle, admin := NewCBCBitflipOracle()
	c := SolveCBCBitflipOracle(oracle)

	if !admin(c) {
		t.Error("expected to get admin access, but the ciphertext is", c)
	}
}
