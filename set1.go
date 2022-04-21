// set1.go provides primitives for solving set 1 of the cryptopals challenges.

package cryptopals

import (
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"math"
	"math/bits"
	"unicode"

	"golang.org/x/exp/constraints"
)

// HexToBase64 takes a hex-encoded string, decoding it as a byte slice and
// re-encoding it in base64 format.
func HexToBase64(hs string) (string, error) {
	s, err := hex.DecodeString(hs)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(s), nil
}

// XorSlice takes two integer slices and XORs the first slice by the second
// one. Callers should be careful to ensure that the length of y is greater than
// zero to avoid divide by 0.
func XorSlice[T constraints.Integer](x, y []T) []T {
	res := make([]T, len(x))
	for i := range x {
		res[i] = x[i] ^ y[i%len(y)]
	}
	return res
}

// SingleXor XORs an integer slice by an integer.
func SingleXor[T constraints.Integer](x []T, key T) []T {
	res := make([]T, len(x))
	for i := range x {
		res[i] = x[i] ^ key
	}
	return res
}

// ScoreString scores how the string is in-line with the most frequent English
// letters.
func ScoreString(s string) (count float64) {
	for _, r := range s {
		if f, ok := frequency[unicode.ToLower(r)]; ok {
			count += f
		}
	}
	return
}

// GuessKey automates iterating over 0..255 SingleXors, returning the single
// byte key with the highest scoring string along with the score.
func GuessKey(src []byte) (key byte, high float64) {
	for i := 0; i < 256; i++ {
		s := SingleXor(src, byte(i))
		score := ScoreString(string(s))

		if score > high {
			key, high = byte(i), score
		}
	}
	return
}

// ComputeHammering counts the differing bits in the strings by xoring them
// together and counting the remaining bits.
func ComputeHamming(x, y []byte) (count int) {
	for _, b := range XorSlice(x, y) {
		count += bits.OnesCount8(b)
	}
	return
}

// averageChunks compares the hamming distance of the first chunk with every
// other chunk. Instead of comparing just two or four chunks, I decided to
// compare all of them and average the result to ensure I get connsistent
// results. Only taking the first couple of chunk yields the wrong key size.
func averageChunks(src []byte, size int) (avg float64) {
	var i int
	for i = range src {
		if size*(i+2) > len(src) {
			break // not enough chunk for us to look ahead
		}

		// compute the hammering distance between the first chunk and chunk[i]...
		avg += float64(ComputeHamming(src[:size], src[size*(i+1):size*(i+2)]))
	}
	return avg / float64(i)
}

// FindXorKeySize is a probabilistic search for the key length in a range of
// 2..40. This is done by exploiting the fact that English has a lower hamming
// distance than random bytes; utilizing this property allows us to perform a
// search for the length of the key.
//
// If our two chunks (x, y) are indeed the length of the key, we can expect the
// hamming distance between them to be exactly the same as their actual hamming
// distance. We can test this by writing a simple function.
//
//	x, y := []byte{1, 3, 3, 7}, []byte{10, 14, 14, 15}
//	key := decodeHex("f00d")
//	a, b := ComputeHamming(x, y), ComputeHamming(XorSlice(x, key), XorSlice(y, key))
//	if a != b {
//		panic("oh no this should not happen???")
//	}
//
// See https://crypto.stackexchange.com/a/8118 for more info.
func FindXorKeySize(src []byte) (result int) {
	low := math.MaxFloat64 // we are looking for the lowest hamming distance
	for size := 2; size < 40; size++ {
		score := averageChunks(src, size) / float64(size) // calculate score by computing the edit distance and normalizing it by dividing
		if score < low {
			result, low = size, score
		}
	}
	return
}

// TransposeBytes takes an integer slice and creates a slice of length size,
// then transposes those bytes appropriately.
func TransposeBytes(src []byte, size int) [][]byte {
	res := make([][]byte, size)
	for i := range src {
		res[i%size] = append(res[i%size], src[i])
	}
	return res
}

// FindTransposedXorKey guesses the key by taking transposing the byte slice
// into chunks of length size and attempting to solve each chunk via GuessKey.
func FindTransposedXorKey(src []byte, size int) []byte {
	key := make([]byte, size)
	blocks := TransposeBytes(src, size)
	for i := range blocks {
		key[i], _ = GuessKey(blocks[i])
	}
	return key
}

// DecryptECB decrypts a byte slice encrypted in ECB mode.
func DecryptECB(src []byte, block cipher.Block) []byte {
	dst := make([]byte, len(src))
	for i := 0; i < len(src); i += block.BlockSize() {
		block.Decrypt(dst[i:], src[i:])
	}
	return dst
}

// DetectECB detects if a string is encrypted in ECB mode by checking for the
// existence of identical blocks with a map.
func DetectECB(src []byte, blockSize int) bool {
	m := make(map[string]struct{})
	for i := 0; i < len(src)/blockSize; i++ {
		block := string(src[i*blockSize : (i+1)*blockSize])
		if _, ok := m[block]; ok {
			return true
		}
		m[block] = struct{}{}
	}
	return false
}

// letter frequencies are from
// http://www.macfreek.nl/memory/Letter_Distribution.
var frequency = map[rune]float64{
	' ': .18288,
	'e': .10267,
	't': .07517,
	'a': .06532,
	'o': .06160,
	'n': .05712,
	'i': .05668,
	's': .05317,
	'r': .04988,
	'h': .04979,
	'l': .03318,
	'd': .03283,
	'u': .02276,
	'c': .02234,
	'm': .02027,
	'f': .01983,
	'w': .01704,
	'g': .01625,
	'p': .01504,
	'y': .01428,
	'b': .01259,
	'v': .00796,
	'k': .00560,
	'x': .00141,
	'j': .00097,
	'q': .00837,
	'z': .00051,
}
