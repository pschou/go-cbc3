package cbc3

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha256"
	"testing"

	cbc3 "github.com/pschou/go-cbc3"
)

var benchmark_size = 1488000
var benchkey []byte

func init() {
	hash := sha256.Sum256([]byte("testit"))
	benchkey = hash[:]
}

func BenchmarkCBC_DES_Decrypt(b *testing.B) {
	b1, _ := des.NewCipher(benchkey[:8])

	iv := make([]byte, 8)
	ciphertext := make([]byte, benchmark_size)

	mode := cipher.NewCBCDecrypter(b1, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	for n := 0; n < b.N; n++ {
		mode.CryptBlocks(ciphertext, ciphertext)
	}
}
func BenchmarkCBC_DES_Encrypt(b *testing.B) {
	b1, _ := des.NewCipher(benchkey[:8])

	iv := make([]byte, 8)
	ciphertext := make([]byte, benchmark_size)

	mode := cipher.NewCBCEncrypter(b1, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	for n := 0; n < b.N; n++ {
		mode.CryptBlocks(ciphertext, ciphertext)
	}
}
func BenchmarkCBC_3DES_Decrypt(b *testing.B) {
	b1, _ := des.NewTripleDESCipher(benchkey[:24])

	iv := make([]byte, 8)
	ciphertext := make([]byte, benchmark_size)

	mode := cipher.NewCBCDecrypter(b1, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	for n := 0; n < b.N; n++ {
		mode.CryptBlocks(ciphertext, ciphertext)
	}
}
func BenchmarkCBC_3DES_Encrypt(b *testing.B) {
	b1, _ := des.NewTripleDESCipher(benchkey[:24])

	iv := make([]byte, 8)
	ciphertext := make([]byte, benchmark_size)

	mode := cipher.NewCBCEncrypter(b1, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	for n := 0; n < b.N; n++ {
		mode.CryptBlocks(ciphertext, ciphertext)
	}
}
func BenchmarkCBC3_DES_Decrypt(b *testing.B) {
	b1, _ := des.NewCipher(benchkey[:8])
	b2, _ := des.NewCipher(benchkey[8:16])
	b3, _ := des.NewCipher(benchkey[16:24])

	iv := make([]byte, 24)
	ciphertext := make([]byte, benchmark_size)

	mode := cbc3.NewDecrypter(b1, b2, b3, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	for n := 0; n < b.N; n++ {
		mode.CryptBlocks(ciphertext, ciphertext)
	}
}

func BenchmarkCBC3_DES_Encrypt(b *testing.B) {
	b1, _ := des.NewCipher(benchkey[:8])
	b2, _ := des.NewCipher(benchkey[8:16])
	b3, _ := des.NewCipher(benchkey[16:24])

	iv := make([]byte, 24)
	ciphertext := make([]byte, benchmark_size)

	mode := cbc3.NewEncrypter(b1, b2, b3, iv)
	for n := 0; n < b.N; n++ {
		mode.CryptBlocks(ciphertext, ciphertext)
	}
}

func BenchmarkCBC_AES128_Decrypt(b *testing.B) {
	b1, _ := aes.NewCipher(benchkey[:16])

	iv := make([]byte, 16)
	ciphertext := make([]byte, benchmark_size)

	mode := cipher.NewCBCDecrypter(b1, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	for n := 0; n < b.N; n++ {
		mode.CryptBlocks(ciphertext, ciphertext)
	}
}
func BenchmarkCBC_AES128_Encrypt(b *testing.B) {
	b1, _ := aes.NewCipher(benchkey[:16])

	iv := make([]byte, 16)
	ciphertext := make([]byte, benchmark_size)

	mode := cipher.NewCBCEncrypter(b1, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	for n := 0; n < b.N; n++ {
		mode.CryptBlocks(ciphertext, ciphertext)
	}
}
func BenchmarkCBC_AES192_Decrypt(b *testing.B) {
	b1, _ := aes.NewCipher(benchkey[:24])

	iv := make([]byte, 16)
	ciphertext := make([]byte, benchmark_size)

	mode := cipher.NewCBCDecrypter(b1, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	for n := 0; n < b.N; n++ {
		mode.CryptBlocks(ciphertext, ciphertext)
	}
}
func BenchmarkCBC_AES192_Encrypt(b *testing.B) {
	b1, _ := aes.NewCipher(benchkey[:24])

	iv := make([]byte, 16)
	ciphertext := make([]byte, benchmark_size)

	mode := cipher.NewCBCEncrypter(b1, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	for n := 0; n < b.N; n++ {
		mode.CryptBlocks(ciphertext, ciphertext)
	}
}
func BenchmarkCBC_AES256_Decrypt(b *testing.B) {
	b1, _ := aes.NewCipher(benchkey[:32])

	iv := make([]byte, 16)
	ciphertext := make([]byte, benchmark_size)

	mode := cipher.NewCBCDecrypter(b1, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	for n := 0; n < b.N; n++ {
		mode.CryptBlocks(ciphertext, ciphertext)
	}
}
func BenchmarkCBC_AES256_Encrypt(b *testing.B) {
	b1, _ := aes.NewCipher(benchkey[:32])

	iv := make([]byte, 16)
	ciphertext := make([]byte, benchmark_size)

	mode := cipher.NewCBCEncrypter(b1, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	for n := 0; n < b.N; n++ {
		mode.CryptBlocks(ciphertext, ciphertext)
	}
}
func BenchmarkCBC3_AES128_Decrypt(b *testing.B) {
	b1, _ := aes.NewCipher(benchkey[:16])
	b2, _ := aes.NewCipher(benchkey[:16])
	b3, _ := aes.NewCipher(benchkey[:16])

	iv := make([]byte, 16*3)
	ciphertext := make([]byte, benchmark_size)

	mode := cbc3.NewDecrypter(b1, b2, b3, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	for n := 0; n < b.N; n++ {
		mode.CryptBlocks(ciphertext, ciphertext)
	}
}
func BenchmarkCBC3_AES128_Encrypt(b *testing.B) {
	b1, _ := aes.NewCipher(benchkey[:16])
	b2, _ := aes.NewCipher(benchkey[:16])
	b3, _ := aes.NewCipher(benchkey[:16])

	iv := make([]byte, 16*3)
	ciphertext := make([]byte, benchmark_size)

	mode := cbc3.NewEncrypter(b1, b2, b3, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	for n := 0; n < b.N; n++ {
		mode.CryptBlocks(ciphertext, ciphertext)
	}
}
func BenchmarkCBC3_AES192_Decrypt(b *testing.B) {
	b1, _ := aes.NewCipher(benchkey[:24])
	b2, _ := aes.NewCipher(benchkey[:24])
	b3, _ := aes.NewCipher(benchkey[:24])

	iv := make([]byte, 16*3)
	ciphertext := make([]byte, benchmark_size)

	mode := cbc3.NewDecrypter(b1, b2, b3, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	for n := 0; n < b.N; n++ {
		mode.CryptBlocks(ciphertext, ciphertext)
	}
}
func BenchmarkCBC3_AES192_Encrypt(b *testing.B) {
	b1, _ := aes.NewCipher(benchkey[:24])
	b2, _ := aes.NewCipher(benchkey[:24])
	b3, _ := aes.NewCipher(benchkey[:24])

	iv := make([]byte, 16*3)
	ciphertext := make([]byte, benchmark_size)

	mode := cbc3.NewEncrypter(b1, b2, b3, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	for n := 0; n < b.N; n++ {
		mode.CryptBlocks(ciphertext, ciphertext)
	}
}
func BenchmarkCBC3_AES256_Decrypt(b *testing.B) {
	b1, _ := aes.NewCipher(benchkey[:32])
	b2, _ := aes.NewCipher(benchkey[:32])
	b3, _ := aes.NewCipher(benchkey[:32])

	iv := make([]byte, 16*3)
	ciphertext := make([]byte, benchmark_size)

	mode := cbc3.NewDecrypter(b1, b2, b3, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	for n := 0; n < b.N; n++ {
		mode.CryptBlocks(ciphertext, ciphertext)
	}
}
func BenchmarkCBC3_AES256_Encrypt(b *testing.B) {
	b1, _ := aes.NewCipher(benchkey[:32])
	b2, _ := aes.NewCipher(benchkey[:32])
	b3, _ := aes.NewCipher(benchkey[:32])

	iv := make([]byte, 16*3)
	ciphertext := make([]byte, benchmark_size)

	mode := cbc3.NewEncrypter(b1, b2, b3, iv)
	// CryptBlocks can work in-place if the two arguments are the same.
	for n := 0; n < b.N; n++ {
		mode.CryptBlocks(ciphertext, ciphertext)
	}
}
