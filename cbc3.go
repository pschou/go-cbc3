// Copyright 2019 pschou (github.com/pschou)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// CBC3, Tripled Cipher Block Chaining, provides an inner-CBC method by XORing
// (chaining) each plaintext block with the previous ciphertext block while
// applying three block ciphers.  The block ciphers do not need to be of the
// same kind, but they must match when decrypting.

// Triple-CBC enables the ability to do SSH-1 style Triple-DES.  This is done
// by wrapping this CBC3 around the three DES block cipher. As SSH-1 replicates
// the whole CBC structure three times, there have to be three separate IVs,
// one in each of the two layers (outer and inner).

package cbc3 // import "github.com/pschou/go-cbc3"

import (
	"crypto/cipher"
	"unsafe"
)

type cbc struct {
	b1, b2, b3 cipher.Block
	blockSize  int
	iv         []byte
	tmp        []byte
}

func newCBC3(b1, b2, b3 cipher.Block, iv []byte) *cbc {
	return &cbc{
		b1:        b1,
		b2:        b2,
		b3:        b3,
		blockSize: b1.BlockSize(),
		iv:        dup(iv),
		tmp:       make([]byte, b1.BlockSize()),
	}
}

type cbc3Encrypter cbc

// NewEncrypter returns a BlockMode which encrypts in cipher block chaining
// mode, using the given three Blocks, all of which must have the same block
// size. The length of iv must be the same as the three times the Block's block
// size.  It is recommended that the blocks be initialized with different IVs.
func NewEncrypter(b1, b2, b3 cipher.Block, iv []byte) cipher.BlockMode {
	bs := b1.BlockSize()
	if bs != b2.BlockSize() || bs != b3.BlockSize() {
		panic("cbc3.NewEncrypter: BlockSize must be equal for all three block ciphers")
	}
	if len(iv) != 3*bs {
		panic("cbc3.NewEncrypter: IV length must equal three times the cipher block size")
	}
	return (*cbc3Encrypter)(newCBC3(b1, b2, b3, iv))
}

func (x *cbc3Encrypter) BlockSize() int { return x.blockSize }

func (x *cbc3Encrypter) CryptBlocks(dst, src []byte) {
	// Check input for sane values
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	if inexactOverlap(dst[:len(src)], src) {
		panic("crypto/cipher: invalid buffer overlap")
	}

	iv0 := x.iv[:x.blockSize]
	iv1 := x.iv[x.blockSize : 2*x.blockSize]
	iv2 := x.iv[2*x.blockSize:]

	for len(src) > 0 {
		/* Do three passes of CBC, with the middle one inverted. */

		xorBytes(dst[:x.blockSize], src[:x.blockSize], iv0)
		x.b1.Encrypt(dst[:x.blockSize], dst[:x.blockSize])
		copy(iv0, dst[:x.blockSize])

		x.b2.Decrypt(dst[:x.blockSize], dst[:x.blockSize])
		xorBytes(dst[:x.blockSize], dst[:x.blockSize], iv1)
		copy(iv1, iv0)

		xorBytes(dst[:x.blockSize], dst[:x.blockSize], iv2)
		x.b3.Encrypt(dst[:x.blockSize], dst[:x.blockSize])
		copy(iv2, dst[:x.blockSize])

		// Move to the next block
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

func (x *cbc3Encrypter) SetIV(iv []byte) {
	if len(iv) != len(x.iv) {
		panic("cipher: incorrect length IV")
	}
	copy(x.iv, iv)
}

type cbc3Decrypter cbc

// NewDecrypter returns a BlockMode which decrypts in cipher block chaining
// mode, using the given three Blocks, all of which must have the same block
// size. The length of iv must be the same as the three times the Block's block
// size and must match the iv used to encrypt the data.
func NewDecrypter(b1, b2, b3 cipher.Block, iv []byte) cipher.BlockMode {
	bs := b1.BlockSize()
	if bs != b2.BlockSize() || bs != b3.BlockSize() {
		panic("cbc3.NewDecrypter: BlockSize must be equal for all three block ciphers")
	}
	if len(iv) != 3*bs {
		panic("cbc3.NewDecrypter: IV length must equal three times the cipher block size")
	}
	return (*cbc3Decrypter)(newCBC3(b1, b2, b3, iv))
}

func (x *cbc3Decrypter) BlockSize() int { return x.blockSize }

func (x *cbc3Decrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	if inexactOverlap(dst[:len(src)], src) {
		panic("crypto/cipher: invalid buffer overlap")
	}
	if len(src) == 0 {
		return
	}

	iv0 := x.iv[:x.blockSize]
	iv1 := x.iv[x.blockSize : 2*x.blockSize]
	iv2 := x.iv[2*x.blockSize:]

	for len(src) > 0 {
		/* Do three passes of CBC, with the middle one inverted. */
		copy(x.tmp, src[:x.blockSize])
		x.b3.Decrypt(dst[:x.blockSize], src[:x.blockSize])
		xorBytes(dst[:x.blockSize], dst[:x.blockSize], iv2)
		copy(iv2, x.tmp)

		xorBytes(dst[:x.blockSize], dst[:x.blockSize], iv1)
		x.b2.Encrypt(dst[:x.blockSize], dst[:x.blockSize])
		copy(iv1, dst[:x.blockSize])

		x.b1.Decrypt(dst[:x.blockSize], dst[:x.blockSize])
		xorBytes(dst[:x.blockSize], dst[:x.blockSize], iv0)
		copy(iv0, iv1)

		// Move to the next block
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

func (x *cbc3Decrypter) SetIV(iv []byte) {
	if len(iv) != len(x.iv) {
		panic("cipher: incorrect length IV")
	}
	copy(x.iv, iv)
}

func dup(p []byte) []byte {
	q := make([]byte, len(p))
	copy(q, p)
	return q
}

// AnyOverlap reports whether x and y share memory at any (not necessarily
// corresponding) index. The memory beyond the slice length is ignored.
func anyOverlap(x, y []byte) bool {
	return len(x) > 0 && len(y) > 0 &&
		uintptr(unsafe.Pointer(&x[0])) <= uintptr(unsafe.Pointer(&y[len(y)-1])) &&
		uintptr(unsafe.Pointer(&y[0])) <= uintptr(unsafe.Pointer(&x[len(x)-1]))
}

// InexactOverlap reports whether x and y share memory at any non-corresponding
// index. The memory beyond the slice length is ignored. Note that x and y can
// have different lengths and still not have any inexact overlap.
//
// InexactOverlap can be used to implement the requirements of the crypto/cipher
// AEAD, Block, BlockMode and Stream interfaces.
func inexactOverlap(x, y []byte) bool {
	if len(x) == 0 || len(y) == 0 || &x[0] == &y[0] {
		return false
	}
	return anyOverlap(x, y)
}

// defined in crypto/cipher/xor.go
func xorBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}
	return n
}
