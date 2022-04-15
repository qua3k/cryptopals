// set1_test.go provides the actual challenges to solve

package cryptopals

import (
	"bufio"
	"crypto/aes"
	"encoding/hex"
	"os"
	"testing"
)

func TestChallenge1(t *testing.T) {
	bs, _ := HexToBase64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")

	// expected value
	assert(t, "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", bs)
}

func TestChallenge2(t *testing.T) {
	x, y := decodeHex("1c0111001f010100061a024b53535009181c"), decodeHex("686974207468652062756c6c277320657965")
	r := hex.EncodeToString(XorSlice(x, y))

	// expected value
	assert(t, "746865206b696420646f6e277420706c6179", r)
}

func TestChallenge3(t *testing.T) {
	b := decodeHex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")

	key, _ := GuessKey(b)
	likely := string(SingleXor(b, key))

	// expected value
	assert(t, "Cooking MC's like a pound of bacon", likely)
}

func TestChallenge4(t *testing.T) {
	const filename = "testdata/4.txt"
	f, err := os.Open(filename)
	if err != nil {
		t.Errorf("could not open %s failed with error %v\n", filename, err)
	}
	defer f.Close()

	var likely string
	var high float64

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		b := decodeHex(scanner.Text())
		key, score := GuessKey(b)
		if score > high {
			likely, high = string(SingleXor(b, key)), score
		}
	}

	if err := scanner.Err(); err != nil {
		t.Error(err)
	}

	// expected value
	assert(t, "Now that the party is jumping\n", likely)
}

func TestChallenge5(t *testing.T) {
	const (
		stanza = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
		key    = "ICE"
	)

	s := hex.EncodeToString(XorSlice([]byte(stanza), []byte(key)))

	// expected value
	assert(t, "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", s)
}

func TestHammingDistance(t *testing.T) {
	x, y := []byte{1, 3, 3, 7}, []byte{10, 14, 14, 15}
	key := decodeHex("f00d")

	a, b := ComputeHamming(x, y), ComputeHamming(XorSlice(x, key), XorSlice(y, key))
	if a != b {
		t.Error("oh no")
	}
}

func TestChallenge6(t *testing.T) {
	// validate our hamming computation is correct
	x, y := []byte("this is a test"), []byte("wokka wokka!!!")
	if c := ComputeHamming(x, y); c != 37 {
		t.Error("should have gotten 37, instead got", c)
	}

	f, err := os.ReadFile("testdata/6.txt")
	if err != nil {
		t.Error("reading testdata/6.txt failed with error:", err)
	}

	d := decodeBase64(f)
	size := FindXorKeySize(d)

	t.Log("the key size is likely", size)
	// expected value
	if size != 29 {
		t.Error("expected 29, instead got", size)
	}

	key := FindTransposedXorKey(d, size)
	t.Logf("the key is likely '%s'\n", key)

	// expected value
	assert(t, "Terminator X: Bring the noise", string(key))

	text := XorSlice(d, key)
	t.Log("our text is:", string(text))
}

func TestChallenge7(t *testing.T) {
	const filename = "testdata/7.txt"

	f, err := os.ReadFile(filename)
	if err != nil {
		t.Errorf("could not open %s, failed with: error %v\n", filename, err)
	}

	d := decodeBase64(f)

	b, err := aes.NewCipher([]byte("YELLOW SUBMARINE"))
	if err != nil {
		t.Error("creating new aes cipher failed with error:", err)
	}

	text := string(DecryptECB([]byte(d), b))
	t.Logf("our text is:\n%s\n", text)
}

func TestChallenge8(t *testing.T) {
	const filename = "testdata/8.txt"

	f, err := os.Open(filename)
	if err != nil {
		t.Errorf("could not open %s, failed with error %v\n", filename, err)
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	var i int
	var text string

	for scanner.Scan() {
		b := decodeHex(scanner.Text())
		if DetectECB(b, 16) {
			text = string(b)
			break
		}
		i++
	}

	// expected value
	if i != 132 {
		t.Error("expected to detect the ciphertext at line 132, instead got", i)
	}
	t.Logf("ciphertext at line %d (%s) is encrypted with ECB.\n", i, text)
}
