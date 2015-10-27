// Program tests the key derivation of golang packages and compares the results
// to those of Dr. Brian Gladman's WinZip AES crypto functions.
// His website is at: http://www.gladman.me.uk/cryptography_technology/fileencrypt/
package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// WinZip AES specifies
//  1. Encryption-Decryption w/ AES-CTR (128, 192, or 256bits)
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
//  5. Authentication with HMAC-SHA1-80 (truncated to 80bits/10bytes).
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
	// Test cases from Dr. Gladman's website.
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

	// Example keys used for AES-128.
	t := tests[1]
	ek, ak, pv := GenerateKeys(t.password, t.salt, AES_128)
	var key bytes.Buffer
	key.Write(ek)
	key.Write(ak)
	key.Write(pv)
	fmt.Printf("PW->Key: %x\n", key.Bytes())
	fmt.Printf("Encryption key: %x\n", ek)
	fmt.Printf("Authentication key: %x\n", ak)
	fmt.Printf("PW Verify Code: %x\n\n", pv)

	// Example keys used for AES-256
	enc, auth, pwv := GenerateKeys(t.password, t.salt, AES_256)
	fmt.Printf("Encryption key: %x\n", enc)
	fmt.Printf("Authentication key: %x\n", auth)
	fmt.Printf("PW Verify Code: %x\n", pwv)
	fmt.Printf("len(enc)+len(auth)+len(pwv)=%d\n", len(enc)+len(auth)+len(pwv))

	// This is the encrypted file data segment from hello.zip
	data := []byte{0x09, 0x89, 0xB4, 0x63, 0x06, 0xBD, 0x8F, 0x82, 0x93,
		0xA3, 0x89, 0x61, 0x3D, 0xB8, 0x26, 0xD1, 0xA3, 0xE6, 0xE0, 0xBA,
		0x87, 0x6C, 0xD1, 0x16, 0xA6, 0xDF, 0x91, 0xCF, 0x7F, 0x8A, 0x14,
		0xB8, 0x9F, 0x23, 0xE3, 0x99, 0xCB, 0x17, 0xD5, 0x65, 0x1A,
	}

	salt := data[:16]
	pv = data[16:18]
	d := data[18:31]
	acode := data[31:]
	fmt.Printf("\nTesting decryption of zip.\n")
	fmt.Printf("Raw Encrypted Zip Data\n")
	fmt.Printf("Salt: %x\n", salt)
	fmt.Printf("PWV: %x\n", pv)
	fmt.Printf("Data: %x\n", d)
	fmt.Printf("AuthCode: %x\n\n", acode)

	// Generate Keys
	enc, auth, pwv = GenerateKeys([]byte("golang"), salt, AES_256)
	fmt.Printf("Encryption key: %x\n", enc)
	fmt.Printf("Auth Key: %x\n", auth)
	fmt.Printf("PWV Code: %x\n\n", pwv)

	// Check password verification code
	if !bytes.Equal(pv, pwv) {
		fmt.Printf("Password verification failed.\n")
		return
	} else {
		fmt.Printf("Password verification passed.\n")
	}

	// Check authentication code
	if !CheckMAC(d, acode, auth) {
		fmt.Printf("Authentication failed.\n")
		return
	} else {
		fmt.Printf("Authentication passed.\n")
	}

	// Finally decrypt
	p := make([]byte, len(d))
	iv := make([]byte, aes.BlockSize)
	iv[0] = 1 // IV starts at 1 not 0. WHY?!?!? Everything I've read says its starts at 0
	fmt.Printf("IV: % x\n", iv)

	var n int32
	buf := bytes.NewReader(iv)
	binary.Read(buf, binary.LittleEndian, &n)
	fmt.Printf("IVint: %d\n", n)

	if !Decrypt(d, p, enc, iv) {
		fmt.Printf("Decryption failed.\n")
		return
	} else {
		fmt.Printf("Decryption succeeded.\n")
	}
	fmt.Printf("Plaintext: %q\n", p)
}

// Key sizes for the auth and enc keys.
const (
	AES_128 = 16
	AES_192 = 24
	AES_256 = 32
)

const (
	iterationCount = 1000
)

// GenerateKeys will create an auth key, encryption key, and pw verification code
// from the password and salt.
func GenerateKeys(password, salt []byte, keySize int) (enc, auth, pv []byte) {
	totalSize := (keySize * 2) + 2 // enc + auth + pv sizes

	key := pbkdf2.Key(password, salt, iterationCount, totalSize, sha1.New)
	enc = key[:keySize]
	auth = key[keySize : keySize*2]
	pv = key[keySize*2:]
	return
}

func CheckMAC(message, messageMAC, key []byte) bool {
	mac := hmac.New(sha1.New, key)
	mac.Write(message)
	expectedMAC := mac.Sum(nil)
	expectedMAC = expectedMAC[:10]
	return bytes.Equal(messageMAC, expectedMAC)
}

func Decrypt(ciphertext, plaintext, key, iv []byte) bool {
	block, err := aes.NewCipher(key)
	if err != nil {
		return false
	}
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)
	return true
}
