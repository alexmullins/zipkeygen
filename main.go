// Program tests the key derivation of golang packages and compares the results
// to those of Dr. Brian Gladman's WinZip AES crypto functions.
// His website is at: http://www.gladman.me.uk/cryptography_technology/fileencrypt/
package main

import (
	"bytes"
	"crypto/sha1"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// WinZip AES specifies
//  1. Encrpytion-Decryption w/ AES-CTR (128, 192, 256)
//  2. KeyGen with PBKDF2-HMAC-SHA1 (1000 iteration count):
//      a. First m bytes is for the encryption key
//      b. Next n bytes is for the authentication key
//      c. Last 2 bytes is the password verification value.
//  3. Following salt lengths are used w/ password during keygen:
//      AES Key Size    | Salt Size
//      ------------------------------
//      128bit(16bytes) | 8 bytes
//      192bit(24bytes) | 12 bytes
//      256bit(32bytes) | 16 bytes
//
//  4. Authentication Key is same size as AES key.
//  5. Authentication with HMAC-SHA1-80 (truncated to 80bits).
//  6. Total key size for PBKDF2 is AES Key Size + Auth Key Size + 2 bytes
//      a. AES 128 = 16 + 16 + 2 = 34 bytes of key material
//      b. AES 192 = 24 + 24 + 2 = 50 bytes of key material
//      c. AES 256 = 32 + 32 + 2 = 66 bytes of key material

var testLen = 16

type test struct {
	password      []byte
	salt          []byte
	keyLen        int
	iterations    int
	firstKeyBytes []byte
}

func main() {
	tests := []test{
		{
			password:   []byte("password"),
			salt:       []byte{0x12, 0x34, 0x56, 0x78},
			keyLen:     32,
			iterations: 5,
			firstKeyBytes: []byte{0x5c, 0x75, 0xce, 0xf0, 0x1a, 0x96, 0x0d, 0xf7,
				0x4c, 0xb6, 0xb4, 0x9b, 0x9e, 0x38, 0xe6, 0xb5},
		},
		{
			password:   []byte("password"),
			salt:       []byte{0x12, 0x34, 0x56, 0x78, 0x78, 0x56, 0x34, 0x12},
			keyLen:     32,
			iterations: 5,
			firstKeyBytes: []byte{0xd1, 0xda, 0xa7, 0x86, 0x15, 0xf2, 0x87, 0xe6,
				0xa1, 0xc8, 0xb1, 0x20, 0xd7, 0x06, 0x2a, 0x49},
		},
	}

	for i := range tests {
		key := pbkdf2.Key(tests[i].password, tests[i].salt, tests[i].iterations, tests[i].keyLen, sha1.New)

		fmt.Printf("Test %d\n", i+1)
		fmt.Printf("Expected first %d bytes: %x\n", testLen, tests[i].firstKeyBytes)
		fmt.Printf("Actual first %d bytes: %x\n", testLen, key[:testLen])
		fmt.Printf("Match: %v\n\n", bytes.Equal(tests[i].firstKeyBytes, key[:testLen]))
	}
}
