// set2.go provides primitives for solving set 2 of the cryptopals challenges.

package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	mrand "math/rand"
	"net/url"
	"strings"
)

// PadPKCS7 pads src according to the PKCS#7 spec.
func PadPKCS7(src []byte, size uint8) []byte {
	padLen := int(size) - len(src)%int(size)
	return append(src, bytes.Repeat([]byte{byte(padLen)}, padLen)...)
}

// EncryptCBC encrypts a block by xoring the plaintext block by the previous
// ciphertext block and encrypting with the block cipher.
func EncryptCBC(bl cipher.Block, src []byte, iv []byte) []byte {
	bs := bl.BlockSize()
	if len(src)%bs != 0 {
		panic(errWrongInput)
	}
	if len(iv) != bs {
		panic(errWrongIv)
	}

	res := make([]byte, len(src))
	for i := 0; i < len(src); i += bs {
		b := res[i : i+bs]
		bl.Encrypt(b, XorSlice(src[i:i+bs], iv))
		iv = b
	}
	return res
}

// DecryptCBC decrypts a block by decrypting the ciphertext block and xoring it
// with the previous ciphetext to obtain the plaintext.
func DecryptCBC(bl cipher.Block, src []byte, iv []byte) []byte {
	bs := bl.BlockSize()
	if len(src)%bs != 0 {
		panic(errWrongInput)
	}
	if len(iv) != bs {
		panic(errWrongIv)
	}

	res := make([]byte, len(src))
	for i := 0; i < len(src); i += bs {
		bl.Decrypt(res[i:], src[i:])
		copy(res[i:], XorSlice(res[i:], iv))
		iv = src[i : i+bs]
	}
	return res
}

// EncryptECB encrypts plaintext using ECB mode.
func EncryptECB(src []byte, bl cipher.Block) []byte {
	bs := bl.BlockSize()
	if len(src)%bs != 0 {
		panic(errWrongInput)
	}
	dst := make([]byte, len(src))
	for i := 0; i < len(src); i += bs {
		bl.Encrypt(dst[i:], src[i:])
	}
	return dst
}

// GenRandKey generates a cryptographically random key of length size.
func GenRandKey(size int) []byte {
	res := make([]byte, size)
	rand.Read(res)
	return res
}

// NewCBCECBOracle takes a plaintext and encrypts it with AES, choosing ECB mode
// or CBC mode randomly. The key (and IV for CBC mode) are cryptographically
// secure, using the crypto/rand package.
func NewCBCECBOracle() func([]byte) []byte {
	b, _ := aes.NewCipher(GenRandKey(16))
	return func(src []byte) (res []byte) {
		prefix, suffix := make([]byte, mrand.Intn(5)+5), make([]byte, mrand.Intn(5)+5)
		rand.Read(prefix)
		rand.Read(suffix)
		src = append(append(prefix, src...), suffix...)
		src = PadPKCS7(src, uint8(b.BlockSize()))

		if mrand.Intn(2) == 0 {
			res = EncryptECB(src, b)
			return
		}

		iv := GenRandKey(b.BlockSize())
		return EncryptCBC(b, src, iv)
	}
}

// NewAppendECBOracle creates a new ECB oracle that appends the specified
// secret, padding appropriately and encrypting the input in ECB mode.
func NewAppendECBOracle(secret string) func([]byte) []byte {
	b, _ := aes.NewCipher(GenRandKey(16))
	return func(src []byte) []byte {
		res := PadPKCS7(append(src, decodeBase64([]byte(secret))...), uint8(b.BlockSize()))
		return EncryptECB(res, b)
	}
}

// findBlockSize attempts to brute force the block size of an ECB oracle by
// looking for identical, adjacent blocks. Returns 0 if the text is not
// encrypted in ECB mode.
func findBlockSize(oracle func([]byte) []byte) (bs int) {
	var ecb bool
	for bs = 3; bs < 64; bs++ {
		b := bytes.Repeat([]byte{'A'}, bs*3)
		if DetectECB(oracle(b), bs) {
			ecb = true
			break
		}
	}

	if !ecb {
		return 0
	}
	return
}

// DecryptAppendOracle attempts to recover appended plaintext given by
// NewAppendECBOracle.
func DecryptAppendOracle(oracle func([]byte) []byte) []byte {
	bs := findBlockSize(oracle)
	if bs == 0 {
		panic("not using ECB mode")
	}

	// constructFirstMap constructs a map of ciphertexts given an oracle.
	constructFirstMap := func(src []byte) map[string]byte {
		res := map[string]byte{}
		for i := 0; i < 128; i++ { // for the sake of time let's stick to 128
			c := oracle(append(src, byte(i)))
			res[string(c[:bs])] = uint8(i)
		}
		return res
	}

	findNext := func(first, pattern []byte, current int) byte {
		for i := 0; i < 128; i++ {
			f := append(first, byte(i))
			c := oracle(append(f, pattern...))

			pos := current*bs + bs // skip a block to account for primer
			if string(c[:bs]) == string(c[pos:pos+bs]) {
				return byte(i)
			}
		}
		return 0
	}

	res := make([]byte, len(oracle([]byte{})))
	for i := 0; i < len(res); i++ {
		r := bytes.Repeat([]byte{'A'}, mod(bs-i-1, bs))
		current := i / bs

		if current == 0 {
			m := constructFirstMap(append(r, res[:i]...))
			if b, ok := m[string(oracle(r)[:bs])]; ok {
				res[i] = b
			}
			continue
		}
		res[i] = findNext(res[i-bs+1:i], r, current)
	}
	return res
}

// GenerateProfile takes an email and encodes it into "URL encoded" form.
func GenerateProfile(email string) string {
	v := url.Values{}
	v.Set("email", email)
	v.Set("uid", "10")
	v.Set("role", "user")

	return v.Encode()
}

// NewProfileOracle returns an oracle that takes an email, generates a profile
// from it, and encrypts it under ECB mode.
func NewProfileOracle() (oracle func(email string) []byte, block cipher.Block) {
	block, _ = aes.NewCipher(GenRandKey(16))
	return func(email string) []byte {
		p := PadPKCS7([]byte(GenerateProfile(email)), uint8(block.BlockSize()))
		return EncryptECB(p, block)
	}, block
}

// UnpadPKCS7 unpads src by reading the last byte value and deleting the
// specified number of bytes.
func UnpadPKCS7(src []byte, size uint8) []byte {
	if len(src)%int(size) != 0 {
		panic(errWrongInput)
	}

	added := src[len(src)-1]

	padding := src[len(src)-int(added):]
	for i := range padding {
		if padding[i] != added {
			return nil
		}
	}

	return src[:len(src)-int(added)]
}

// DecryptAdmin decrypts the ciphertext and evaluates if it grants admin access.
func DecryptAdmin(src []byte, bl cipher.Block) bool {
	b := DecryptECB(src, bl)
	b = UnpadPKCS7(b, uint8(bl.BlockSize()))

	v, err := url.ParseQuery(string(b))
	if err != nil {
		return false
	}
	return v.Get("role") == "admin"
}

// GenerateAdmin takes advantage of our ability to manipulate blocks to craft a
// block with the role key and the admin value in separate blocks.
//
// For instance, the plaintext blocks for email foo@bar.com when blocksize is 16
// looks something like
//  email=foo@bar.co m&role=user&uid=1 0
//
// We can isolate the role key and value to obtain the ability to effectively
// the key to an arbitrary value; it will look like the below.
//	email=AAAA&role= user&uid=10
//
// Afterwards, we can just make a large email that will take up the whole block
// and then some; we can combine these two blocks together to yield
// 	email=AAAA&role= admin&role=user& uid=10
func GenerateAdmin(oracle func(email string) []byte, size int) []byte {
	const e = len("email=")
	const r = len("&role=")

	b := bytes.Repeat([]byte{'A'}, size-e)
	x := oracle(string(b[:len(b)-r]))[0:size]                 // email=AAAA&role=
	y := oracle(string(append(b, "admin"...)))[size : size*3] // admin&role=user& uid=10
	return append(x, y...)                                    // email=AAAA&role= admin&role=user& uid=10
}

// NewPrependECBOracle creates a new ECB oracle that prepends the specified
// secret, padding appropriately and encrypting the input in ECB mode.
func NewPrependECBOracle(secret string) func([]byte) []byte {
	prefix := GenRandKey(mrand.Intn(128))
	b, _ := aes.NewCipher(GenRandKey(16))
	return func(src []byte) []byte {
		src = append(prefix, src...)
		res := PadPKCS7(append(src, decodeBase64([]byte(secret))...), uint8(b.BlockSize()))
		return EncryptECB(res, b)
	}
}

// DecryptPrependOracle is very similar in spirit to DecryptAppendOracle;
// however, there is a random but consistent number of random bytes prepended
// to our plaintext. By consistently padding these bytes out we can
// slice/discard the ciphertext up to our controlled bytes and use
// DecryptAppendOracle to solve.
func DecryptPrependOracle(oracle func([]byte) []byte) []byte {
	// you know the drill; find the block size
	bs := findBlockSize(oracle)
	if bs == 0 {
		panic("not using ECB mode")
	}

	var pos int

	c := oracle(bytes.Repeat([]byte{'A'}, bs*3)) // create two identical blocks; we're using ECB

	m := map[string]int{}
	for i := 0; i < len(c); i += bs {
		b := string(c[i : i+bs]) // a block
		if p, ok := m[b]; ok {   // if we've seen this block before jump out and assign the index of the first controlled block
			pos = p
			break
		}
		m[b] = i
	}

	// we have the position, now we need to know how many bytes to add...
	var needed int
	for i := 0; i < bs; i++ {
		o := oracle(bytes.Repeat([]byte{'A'}, i))[pos-bs : pos]
		p := c[pos-bs : pos]
		if string(o) == string(p) { // if they're identical we know how many bytes to pad
			needed = i
			break
		}
	}

	return DecryptAppendOracle(func(src []byte) []byte {
		// need to append to fill the incomplete block or something
		return oracle(append(bytes.Repeat([]byte{'A'}, needed), src...))[pos:]
	})
}

// NewCBCBitflipOracle returns an oracle that takes an input, prepends
// "comment1=cooking%20MCs;userdata=" and appends
// ";comment2=%20like%20a%20pound%20of%20bacon", padding with PKCS#7, as well as
// another function that decrypts the input and checks for the existence of
// ";admin=true;"
func NewCBCBitflipOracle() (oracle func([]byte) []byte, checkAdmin func([]byte) bool) {
	const (
		pre = "comment1=cooking%20MCs;userdata="
		end = ";comment2=%20like%20a%20pound%20of%20bacon"
	)
	bl, _ := aes.NewCipher(GenRandKey(16))
	iv := GenRandKey(bl.BlockSize())

	oracle = func(src []byte) []byte {
		src = bytes.ReplaceAll(src, []byte{';'}, []byte("%3B"))
		src = bytes.ReplaceAll(src, []byte{'='}, []byte("%3D"))

		in := append(append([]byte(pre), src...), end...)
		return EncryptCBC(bl, PadPKCS7(in, uint8(bl.BlockSize())), iv)
	}

	checkAdmin = func(src []byte) bool {
		d := DecryptCBC(bl, src, iv)
		return strings.Contains(string(d), ";admin=true;")
	}
	return
}

// SolveCBCBitflipOracle solves challenge 14 by flipping two bits to get
// `;admin=true;` in the plaintext. This works by taking advantage of how CBC
// decryption works: a plaintext block is the result of decrypting the
// ciphertext and xoring it with the previous block.
//
// If we can control the plaintext, we know that the raw result of the AES
// decryption pass is
//	D[i] ^ C[i-1]
// By editing the same byte in the previous block we can craft a byte that is
//	C[i] ^= NEXT_BYTE_SAME_POSITION ^ TARGET_BYTE
// I've elected to choose the 'X' byte to make this obvious, but it could
// feasibly be any byte.
func SolveCBCBitflipOracle(oracle func([]byte) []byte) []byte {
	o := oracle([]byte("XadminXtrue"))
	o[16] ^= 'X' ^ ';'
	o[22] ^= 'X' ^ '='
	return o
}

var (
	errWrongInput = errors.New("github.com/qua3k/cryptopals: wrong input length")
	errWrongIv    = errors.New("github.com/qua3k/cryptopals: wrong iv length")
)
