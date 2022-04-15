# cryptopals

This is a repo for cryptopals solutions or something.

## Table of Contents

*   [Set 1](#set-1)
    *   [Challenge 1](#challenge-1)
    *   [Challenge 2](#challenge-2)
    *   [Challenge 3](#challenge-3)
    *   [Challenge 4](#challenge-4)
    *   [Challenge 5](#challenge-5)
    *   [Challenge 6](#challenge-6)
    *   [Challenge 7](#challenge-7)
    *   [Challenge 8](#challenge-8)

## Set 1

### Challenge 1

Challenge link: [https://cryptopals.com/sets/1/challenges/1](https://cryptopals.com/sets/1/challenges/1)

This challenge asks us to take a hex-encoded string, decode it into a byte
slice, and re-encode it into base64. This should yield
`SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t`.

### Challenge 2

Challenge link: [https://cryptopals.com/sets/1/challenges/2](https://cryptopals.com/sets/1/challenges/2)

This challenge asks us to take two hex-encoded strings, decoding them into byte
slices, and XORing them together. When re-encoded to hex, this yields
`746865206b696420646f6e277420706c6179`.

Here is a tiny truth table for XOR :)

| A 	| B 	| Output 	|
|---	|---	|--------	|
| 0 	| 0 	| 0      	|
| 0 	| 1 	| 1      	|
| 1 	| 0 	| 1      	|
| 1 	| 1 	| 0      	|

### Challenge 3

Challenge link: [https://cryptopals.com/sets/1/challenges/3](https://cryptopals.com/sets/1/challenges/3)

This challenge asks us to decode a hex-encoded string to a byte slice, brute
forcing it by XORing it with values from 0..255.

We could print the output to console, but that's really inconvenient and
involves a human factor to figure out which sentence actually makes sense. To
solve this challenge effectively we create a `map[runes/bytes]float64`, with the
float being the letter's frequency in English texts. We then do map lookups for
each letter (O(n) time) and add the frequency (f) to the total. Once we loop
through all the values we return the string that scored the highest; this is
probably our value :)

### Challenge 4

Challenge link: [https://cryptopals.com/sets/1/challenges/4](https://cryptopals.com/sets/1/challenges/4)

This challenge asks us to open a file (conveniently located at `testdata/4.txt`)
and apply our logic from challenge 3. We will need to brute force each string
and return the highest scoring plaintext.

### Challenge 5

Challenge link: [https://cryptopals.com/sets/1/challenges/5](https://cryptopals.com/sets/1/challenges/5)

This challenge asks us to look into decrypt a ciphertext encrypted with
repeating-key XOR. We can modify our existing XOR code to instead do `x[i]` XOR
`y[i%len(y)]` (modulo length of y).

### Challenge 6

Challenge link: [https://cryptopals.com/sets/1/challenges/6](https://cryptopals.com/sets/1/challenges/6)

This challenge is definitely the hardest to understand without a background in
cryptography. To make it easier we can break it into multiple sections.

Firstly, we will need to understand the concept of
[hamming distance](https://en.wikipedia.org/wiki/Hamming_distance) at the bit
level. In essence, we are counting the number of differing bits between two
strings of equal length. This can be accomplished by XORing the strings together
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

### Challenge 7

Challenge link: [https://cryptopals.com/sets/1/challenges/7](https://cryptopals.com/sets/1/challenges/7)

This challenge asks us to decrypt a ciphertext encrypted in ECB mode. We use the
[crypto/aes](https://pkg.go.dev/crypto/aes) package, taking decrypting the
ciphertext 16 bytes at a time with `Block.Decrypt`.

### Challenge 8

Challenge link: [https://cryptopals.com/sets/1/challenges/8](https://cryptopals.com/sets/1/challenges/8)

This challenge takes advantage of the fact that AES-ECB encrypts the same
plaintext block into the same ciphertext (lack of diffusion). We track the
encrypted blocks in a map so we can easily lookup the existence of the
ciphertext and determine whether a certain string was encrypted with ECB mode.

[^1]: I looked at Filippo Valsorda's solutions @
[mostly-harmless/](https://github.com/FiloSottile/mostly-harmless/blob/main/cryptopals/set1.go#L97)
as well as his livestream but it turns out he just guessed the magic number;
this isn't good enough for me.
