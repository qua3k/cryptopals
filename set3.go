// set3.go provides primitives for solving set 3 of the cryptopals challenges.

package cryptopals

import (
	"crypto/aes"
	"crypto/cipher"

	"golang.org/x/exp/rand"
)

// NewCBCPaddingOracle crafts a new CBC padding oracle and appends the IV to the ciphertext,
// automatically removing it at decryption time.
func NewCBCPaddingOracle(strs []string) (res []byte, plaintext string, verify func([]byte) bool) {
	iv := GenRandKey(aes.BlockSize)
	bl, _ := aes.NewCipher(GenRandKey(aes.BlockSize))
	blockSize := bl.BlockSize()

	i := rand.Intn(len(strs))
	plaintext = string(decodeBase64String(strs[i]))
	res = EncryptCBC(bl, PadPKCS7([]byte(plaintext), uint8(blockSize)), iv)
	res = append(iv, res...) // prepend the IV

	verify = func(src []byte) bool {
		d := DecryptCBC(bl, src[blockSize:], iv) // remove the IV
		return UnpadPKCS7(d, uint8(blockSize)) != nil
	}
	return
}

func DecryptPaddingOracle(src []byte, blockSize int, padCheck func([]byte) bool) string {
	// We start by appending the IV to the IV + message so we can decrypt the
	// first block.
	src = append(src[:blockSize], src...)
	out := make([]byte, len(src))

	for i := len(src) - 1; i > 2*blockSize-1; i-- {
		prev := i/blockSize*blockSize - 1 // save branches, save lives
		curr := prev + blockSize
		pad := byte(blockSize - i%blockSize)
		var valid bool
		for j := 0; j < 256; j++ {
			j := byte(j)
			if j == pad {
				continue // no change
			}
			out[i] = j
			// xor the whole length of the pad
			for k := 0; k < int(pad); k++ {
				src[prev-k] ^= out[curr-k] ^ pad
			}
			valid = padCheck(src[:curr+1])
			// reset for next
			for k := 0; k < int(pad); k++ {
				src[prev-k] ^= out[curr-k] ^ pad
			}
			if valid {
				break
			}
		}
		// probably the pad value, which we skipped.
		if !valid {
			out[i] = pad
		}
	}
	out = UnpadPKCS7(out, uint8(blockSize))
	return string(out[2*blockSize:])
}

// EncryptCTR encrypts plaintext using ECB mode.
func EncryptCTR(bl cipher.Block, src []byte, nonce []byte) []byte {
	bs := bl.BlockSize()
	sz := len(src)
	dst := make([]byte, sz)
	input, output := make([]byte, bs), make([]byte, bs)
	copy(input, nonce)

	p := len(nonce)

	for i := 0; i < len(src); i += bs {
		bl.Encrypt(output, input)
		input[p]++
		if input[p] == 0 {
			p++
			input[p]++
		}
		for j := 0; i+j < sz && j < bs; j++ {
			output[j] ^= src[i+j]
		}
		copy(dst[i:], output)
	}
	return dst
}

var DecryptCTR = EncryptCTR

func DecryptStream() {

}
