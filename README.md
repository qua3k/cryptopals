# cryptopals

This is a repo providing solutions written in Go to the
[Matasano Cryptopals Challenges](https://cryptopals.com/).

## Challenge 1

This challenge asks us to decode a hex-encoded string into a byte slice and
re-encode it as base64.

## Challenge 2

This challenge asks us to xor two hex-encoded strings together. This can be
accomplished by decoding the strings into byte slices and xoring them together.

Here is a tiny truth table for XOR :)

| A 	| B 	| Output 	|
|---	|---	|--------	|
| 0 	| 0 	| 0      	|
| 0 	| 1 	| 1      	|
| 1 	| 0 	| 1      	|
| 1 	| 1 	| 0      	|

## Challenge 3

This challenge asks us to decode a hex-encoded string xored with a single
character.

We could print the result of `string ⊕ key` where key is 0..255; we would be
able to deduce the correct key by reading the console output, but that doesn't
scale well and is very tedious. To solve this challenge effectively, we can
calculate which output is likely to be the correct one via
[frequency analysis](https://en.wikipedia.org/wiki/Frequency_analysis), assuming
that the string that has the highest frequency count is likely to be the correct
solution. To do this effectively we iterate through the bytes of the output and
lookup their frequency in the English language. Once we loop through all the
values we return the string that "scored" the highest.

## Challenge 4

This challenge asks us to open a file (conveniently located at `testdata/4.txt`)
and apply our logic from challenge 3. We will need to brute force each string
and return the highest scoring plaintext.

## Challenge 5

This challenge asks us to look into decrypt a ciphertext encrypted with
repeating-key XOR. We can modify our existing XOR code to instead do `x[i]` ⊕
`y[i%len(y)]` (modulo length of y).

## Challenge 6

This challenge is definitely the hardest to understand without a background in
cryptography. To make it easier we can break it into multiple sections.

Firstly, we will need to understand the concept of
[hamming distance](https://en.wikipedia.org/wiki/Hamming_distance) at the bit
level. In essence, we are counting the number of differing bits between two
strings of equal length. This can be accomplished by xoring the strings together
and counting the number of bits that are set to one.

As mentioned in the example, we can validate that our code works correctly by
testing it against the strings `this is a test` and `wokka wokka!!!`; it should
come out to 37.

The concept of hamming distance can be applied to help us solve this challenge
when we understand how it interacts with English ASCII. The entire English
alphabet (uppercase and lowercase) is represented in 52 out of the 256 possible
values in ASCII, and it helps that the letters are conveniently located right
next to each other and thus have a normalized average hamming distance far lower
than legitimately random data.

A nice thing to note is that when XOR encrypted with the same key, two strings
have the same hamming distance as their plaintext forms; it is only a matter of
us finding the key length through brute force; the noticeably lower normalized
hamming distance will be our key length :)

The example algorithm as described on the challenge page advises us to attempt
to guess the key length from 2 to 40, which entails taking the first two chunks
of the text of size KEYSIZE (the first block would be `slice[:keysize]`, the
second would be `slice[keysize:keysize*2]`). However, this sample size is too
small to be accurate, which is why they advise taking up to the first four
chunks of the ciphertext and finding the mean among those. In my testing, I
found this to yield the wrong key size still (although it could have just been
buggy code), but I was still determined to figure it out without magic
numbers.[^1]

In my research, I happened upon
[this site discussing this topic in detail](https://carterbancroft.com/breaking-repeating-key-xor-theory)
as well as another set of cryptopals solutions written in Python (I seem to have
lost the link) which prompted me to begin working on code that would iterate
through the length of the ciphertext and compare each chunk
(`slice[size*(i+1):size*(i+2)]`) against the first chunk. This worked as
expected, which allowed us to determine the key size.

Armed with the key size, we attempt to split the ciphertext into chunks of
`len(keysize)`. We transpose the blocks (create a slice of byte slices) by
placing the first byte of each chunk in one slice, the second byte in the
second, and so on. We can then attempt to brute force each byte slice with
scoring + single character XOR; we are then able to reconstruct the key and
ultimately solve the challenge.

## Challenge 7

This challenge asks us to decrypt a ciphertext encrypted in ECB mode. We use the
[crypto/aes](https://pkg.go.dev/crypto/aes) package, decrypting the
ciphertext 16 bytes at a time with `Block.Decrypt`.

## Challenge 8

This challenge takes advantage of the fact that AES-ECB encrypts the same
plaintext block into the same ciphertext (lack of diffusion). We track the
encrypted blocks in a map so we can easily lookup the existence of the
ciphertext and determine whether a certain string was encrypted with ECB mode.

## Challenge 9

This challenge asks us to pad a message to a specific block size with
[PKCS#7](https://datatracker.ietf.org/doc/html/rfc5652#section-6.3). In essence,
this means padding to a specified uint8 length while ensuring the value of the
added bytes is equivalent to the number of bytes added.

## Challenge 10

This challenge asks us to decrypt a AES-CBC encrypted ciphertext. CBC is a
confidentiality-only mode whose encryption can be formalized as
`C[i] = E(P[i] ^ C[i-1])`, with decryption being `P[i] = D(C[i]) ^ C[i-1]`.

## Challenge 11

This challenge asks us to construct an oracle that encrypts a given input with
CBC mode 50% of the time and ECB mode the other half of the time. The key should
be securely generated with the operating system's CSPRNG (see `crypto/rand`) and
it should prepend 5-10 random bytes **and** append 5-10 random bytes to the
plaintext before encryption.

We will use our previous function to detect ECB mode by crafting 3 contiguous
blocks and sending it to the oracle. 3 blocks ensures that no matter how many
bytes are prepended/appended, we will always encrypt two blocks of identical
plaintext.

## Challenge 12

https://book-of-gehn.github.io/articles/2018/06/10/Breaking-ECB.html

## Challenge 13

This challenge asks us to construct a function that will take an arbitrary input
for email (the below map)

    {
        "email": "foo@bar.com",
        "uid":   "10",
        "role":  "user",
    }

and encode it into "URL encoded form" like `email=foo@bar.com&role=user&uid=10`.
This input is then encrypted with ECB mode and the oracle is provided to the
attacker. We aren't able to directly encode the bytes '&' and '=', so we have to
play some clever tricks with padding. We know that the block size is 16 bytes,
so we just have to separate the `key=` and the literal value into separate
blocks. Using a 4 byte email allows us to get exactly this.

    email=AAAA&role= user&uid=10

We can then craft a large email so that the word admin is not in the first
block, and then replace the first block. The plaintext should ultimately look
like the below.

    email=AAAA&role= admin&role=user& uid=10

## Challenge 14

This challenge asks us to extend the previous append-only oracle in Challenge 12
by prepending a consistent, but random number of random bytes. We will need to
pad the prepended bytes to a full block and then solve like Challenge 12.

For instance, if we had the setup

    PPPP PPPP PPAT TACK ERCO NTRO LLED <- appended bytes go here

we should pad the prepended bytes to a full block, like so:

    PPPP PPPP PPXX ATTA CKER CONT ROLL ED <- appended bytes go here
                ^^ padding

then we should craft an oracle that will append the number of padding bytes
consistently when run and solve like 12, so we can have something like the
below:

    PPPP PPPP PPXX <- delete these bytes by slicing
    ATTA CKER CONT ROLL ED <- appended bytes go here

We then solve like normal.

## Challenge 15

This challenge just asks us to modify our unpadding PKCS#7 function to take the
last byte and verify that the added bytes are of the correct number and value.

## Challenge 16

This challenge takes advantage of the lack of authentication of CBC mode to flip
a couple of bits in the ciphertext to get our desired result in the plaintext.

We should think back to our CBC implementation and remember that the result of
the AES decryption pass for each block is the plaintext xored by the previous
ciphertext block. If we can change the previous ciphertext block we can create a
block that looks like `C[i] ^ P[i+1] ^ DESIRED_BYTE`. We can just craft a
plaintext block that looks like `XadminXtrue`, replacing the desired bytes with
the capital X and changing the ciphertext byte in the block immediately prior so
at decryption time it will look like
`C[i-1] (which is really P[i] ^ C[i-1] ^ DESIRED_BYTE) ^ P[i]`, giving us
`DESIRED_BYTE` in the final decrypted plaintext.

[^1]: I looked at Filippo Valsorda's solutions @
[mostly-harmless/](https://github.com/FiloSottile/mostly-harmless/blob/main/cryptopals/set1.go#L97)
as well as his livestream but it turns out he just guessed the magic number;
this isn't good enough for me.