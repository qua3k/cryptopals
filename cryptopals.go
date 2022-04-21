// Package cryptopals provides solutions for set 1 of cryptopals.
//
// This package requires Go 1.18, as it makes use of generics, even though the
// challenges can be solved entirely without them.
package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func assert[T ~string](t *testing.T, x, y T) {
	t.Helper()
	if x != y {
		t.Errorf("Expected %s, instead got %s!\n", x, y)
	}
}

// decodeHex is a simple alias for hex.DecodeString.
func decodeHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

// decodeBase64 decodes a base64 encoded byte slice.
func decodeBase64(in []byte) []byte {
	b, _ := base64.StdEncoding.DecodeString(string(in))
	return b
}

// mod takes the mod of x and y.
func mod(x, y int) int {
	return (x%y + y) % y
}
