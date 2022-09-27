package cbc3

import (
	"crypto/aes"
	"crypto/des"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
)

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

	mode := NewDecrypter(b1, b2, b3, iv)

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

	mode := NewEncrypter(b1, b2, b3, iv)
	mode.CryptBlocks(ciphertext[ivSize:], plaintext)

	// It's important to remember that ciphertexts must be authenticated
	// (i.e. by using crypto/hmac) as well as being encrypted in order to
	// be secure.

	fmt.Printf("%x\n", ciphertext)
}
