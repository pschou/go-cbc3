# go-CBC3

Package CBC implements the triple `inner-CBC` block cipher mode which can be wrapped
around various low-level block cipher implementations.

This package is useful to build compatible frameworks for systems making use of
`inner-CBC` modes.

## Security considerations

A good research paper which touches on this inner-CBC and outer-CBC is here:

E. Biham, "Cryptanalysis of triple-modes of operation," Technion Technical Report CS0885, 1996.
src: http://www.cs.technion.ac.il/users/wwwb/cgi-bin/tr-get.cgi/1996/CS/CS0885.pdf

Biham also makes a point of stating all the triple modes of operation are
theoretically not much more secure than a single encryption.


## 3DES-CBC is not the same as DES with CBC3

Triple DES (3DES) - was DES done three times, and also made to be backwards
compatible.  By backwards compatible, means, if you have three keys (k1, k2,
and k3), the implementation of 3DES (three consecutive ciphers back to back
alternating between encrypt and decrypt) one can now choose a set of keys to
make a 3DES system act like a DES system (if needed).  For example encrypt
(k1), decrypt (k2), and encrypt (k3).  If one were to set k1 == k2 or k2 == k3,
the output would be the same as a single DES.  Hence with hardware which is
designed to do 3DES and needs to work with hardware which does only DES, one
can set two keys equal and get a single DES.  This is not the same as CBC3.

CBC3 - is a tripled Cipher Block Chaining mode agnostic of the block cipher
underneath.  Unlike 3DES vs DES, the notable differences starts with there are
two sets of IVs which inserted into a CBC3, the first set is applied to the
three block ciphers and used to generate the block ciphers, and the second set
is used as an extra layer of XORs operating on each block after being encrypted
or decrypted.



## X5 networks question 73 explaination of inner-CBC
```
With single-DES in CBC mode, the ciphertext is exclusive-ored with the
plaintext before encryption. With triple-DES however, we might use feedback
around all three DES operations from the ciphertext to the plaintext, something
which is called outer-CBC. Alternatively, we might run the feedback around each
individual encryption component, thereby making, in effect, triple-(DES-CBC).
This is referred to as inner-CBC, since there are internal feedbacks that are
never seen by the cryptanalyst.

Performance-wise, there can be some advantages to use the inner-CBC option, but
research has established that outer-CBC is in fact more secure. Outer-CBC is
the recommended way for using triple-DES in the CBC mode.  Src:
http://x5.net/faqs/crypto/q73.html
```


# Benchmarks
For comparison using standard stream block ciphers.  In this test, a payload
sized at 1488 bytes are ciphered.

```
$ go test -bench=.
goos: linux
goarch: amd64
pkg: cbc3
cpu: Intel(R) Xeon(R) CPU           X5650  @ 2.67GHz
BenchmarkCBC_DES_Decrypt-12                32787             37224 ns/op
BenchmarkCBC_DES_Encrypt-12                32798             38315 ns/op
BenchmarkCBC_3DES_Decrypt-12               12301             95460 ns/op
BenchmarkCBC_3DES_Encrypt-12               12622             89542 ns/op
BenchmarkCBC3_DES_Decrypt-12               10000            117193 ns/op ~3x
BenchmarkCBC3_DES_Encrypt-12               10000            111212 ns/op ~3x
BenchmarkCBC_AES128_Decrypt-12            322132              3725 ns/op
BenchmarkCBC_AES128_Encrypt-12            321624              3899 ns/op
BenchmarkCBC_AES192_Decrypt-12            287223              4143 ns/op
BenchmarkCBC_AES192_Encrypt-12            287774              4301 ns/op
BenchmarkCBC_AES256_Decrypt-12            262090              4568 ns/op
BenchmarkCBC_AES256_Encrypt-12            260019              4606 ns/op
BenchmarkCBC3_AES128_Decrypt-12            62209             18196 ns/op ~4.8x
BenchmarkCBC3_AES128_Encrypt-12            63555             18265 ns/op ~4.8x
BenchmarkCBC3_AES192_Decrypt-12            61862             19519 ns/op ~4.6x
BenchmarkCBC3_AES192_Encrypt-12            60960             19929 ns/op ~4.6x
BenchmarkCBC3_AES256_Decrypt-12            58200             21317 ns/op ~4.4x
BenchmarkCBC3_AES256_Encrypt-12            58135             20642 ns/op ~4.4x
```

If the same test is done but with a payload size of 1488000 (1.4MB), one finds
a similar result:

```
$ go test -bench=.
goos: linux
goarch: amd64
pkg: cbc3
cpu: Intel(R) Xeon(R) CPU           X5650  @ 2.67GHz
BenchmarkCBC_DES_Decrypt-12                   31          38549253 ns/op
BenchmarkCBC_DES_Encrypt-12                   32          35722552 ns/op
BenchmarkCBC_3DES_Decrypt-12                  12          92482123 ns/op
BenchmarkCBC_3DES_Encrypt-12                  12          93515554 ns/op
BenchmarkCBC3_DES_Decrypt-12                  10         108331746 ns/op ~3x
BenchmarkCBC3_DES_Encrypt-12                   9         114069439 ns/op ~3x
BenchmarkCBC_AES128_Decrypt-12               319           3729090 ns/op
BenchmarkCBC_AES128_Encrypt-12               318           3764341 ns/op
BenchmarkCBC_AES192_Decrypt-12               288           4149387 ns/op
BenchmarkCBC_AES192_Encrypt-12               282           4253622 ns/op
BenchmarkCBC_AES256_Decrypt-12               254           4654186 ns/op
BenchmarkCBC_AES256_Encrypt-12               254           4733981 ns/op
BenchmarkCBC3_AES128_Decrypt-12               63          18669914 ns/op ~5x
BenchmarkCBC3_AES128_Encrypt-12               62          18550125 ns/op ~5x
BenchmarkCBC3_AES192_Decrypt-12               60          18520923 ns/op ~4.4x
BenchmarkCBC3_AES192_Encrypt-12               67          18034623 ns/op ~4.4x
BenchmarkCBC3_AES256_Decrypt-12               56          20658155 ns/op ~4.4x
BenchmarkCBC3_AES256_Encrypt-12               54          20773274 ns/op ~4.4x
```

Evident from the comparison, the CBC3 mode decreases the cipher speed around
3-5x depending on the block cipher algorithm picked.  The CBC3 mode costs more
per block to cipher.  Theoretically, this tripling does little to improve the
overall quality of the stream cipher. (Biham)

# Examples

## Decryption
```go
func ExampleNewDecrypter() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	hash := sha256.Sum224([]byte("testit"))
	key := hash[:]
	b1, err := des.NewCipher(key[:8])
	if err != nil {
		fmt.Printf("B1 error: %s", err)
	}
	b2, err := des.NewCipher(key[8:16])
	if err != nil {
		fmt.Printf("B2 error: %s", err)
	}
	b3, err := des.NewCipher(key[16:24])
	if err != nil {
		fmt.Printf("B3 error: %s", err)
	}
	ivSize := b1.BlockSize() * 3

	ciphertext, _ := hex.DecodeString("da87200e69c4d5af38720c036849c79a4e3561a32e34613ad04633e7a048a80d0db32b1c6c3ba72e")

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	if len(ciphertext) < ivSize {
		panic("ciphertext too short")
	}
	iv := ciphertext[:ivSize]
	ciphertext = ciphertext[ivSize:]

	mode := cbc3.NewDecrypter(b1, b2, b3, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(ciphertext, ciphertext)

	// If the original plaintext lengths are not a multiple of the block
	// size, padding would have to be added when encrypting, which would be
	// removed at this point. For an example, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. However, it's
	// critical to note that ciphertexts must be authenticated (i.e. by
	// using crypto/hmac) before being decrypted in order to avoid creating
	// a padding oracle.

	fmt.Printf("%s\n", ciphertext)
	// Output: exampleplaintext
}
```

## Encryption
```go
func ExampleNewEncrypter() {
	// Load your secret key from a safe place and reuse it across multiple
	// NewCipher calls. (Obviously don't use this example key for anything
	// real.) If you want to convert a passphrase to a key, use a suitable
	// package like bcrypt or scrypt.
	hash := sha256.Sum224([]byte("testit"))
	key := hash[:]
	b1, err := des.NewCipher(key[:8])
	if err != nil {
		fmt.Printf("B1 error: %s", err)
	}
	b2, err := des.NewCipher(key[8:16])
	if err != nil {
		fmt.Printf("B2 error: %s", err)
	}
	b3, err := des.NewCipher(key[16:24])
	if err != nil {
		fmt.Printf("B3 error: %s", err)
	}
	ivSize := b1.BlockSize() * 3

	plaintext := []byte("exampleplaintext")

	// CBC mode works on blocks so plaintexts may need to be padded to the
	// next whole block. For an example of such padding, see
	// https://tools.ietf.org/html/rfc5246#section-6.2.3.2. Here we'll
	// assume that the plaintext is already of the correct length.
	if len(plaintext)%aes.BlockSize != 0 {
		panic("plaintext is not a multiple of the block size")
	}

	// The IV needs to be unique, but not secure. Therefore it's common to
	// include it at the beginning of the ciphertext.
	ciphertext := make([]byte, ivSize+len(plaintext))
	iv := ciphertext[:ivSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		panic(err)
	}

	mode := cbc3.NewEncrypter(b1, b2, b3, iv)
	mode.CryptBlocks(ciphertext[ivSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	fmt.Printf("%x\n", ciphertext)
}
```
