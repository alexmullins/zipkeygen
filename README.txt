 zipkeygen tests the key derivation of golang's crypto packages and compares the
 results to those of Dr. Brian Gladman's WinZip AES crypto functions.
 His website is at: http://www.gladman.me.uk/cryptography_technology/fileencrypt/

 WinZip AES specifies
  1. Encrpytion-Decryption w/ AES-CTR (128, 192, or 256 bits)
  2. Key generation with PBKDF2-HMAC-SHA1 (1000 iteration count) that
generates a key broken into the following:
        a. First m bytes is for the encryption key
        b. Next n bytes is for the authentication key
        c. Last 2 bytes is the password verification value.
  3. Following salt lengths are used w/ password during keygen:
        AES Key Size    | Salt Size
        ------------------------------
        128bit(16bytes) | 8 bytes
        192bit(24bytes) | 12 bytes
        256bit(32bytes) | 16 bytes
  4. Authentication Key is same size as AES key.
  5. Authentication with HMAC-SHA1-80 (truncated to 80bits).
  6. KeyLen input into PBKDF2: AES Key Size + Auth Key Size + 2 bytes (pw verify)
        a. AES 128 = 16 + 16 + 2 = 34 bytes of key material
        b. AES 192 = 24 + 24 + 2 = 50 bytes of key material
        c. AES 256 = 32 + 32 + 2 = 66 bytes of key material
  7. A new set of encryption/auth keys + salt are generated for each file encrypted
  in the .zip file

Results:
    Test 1
    Expected first 16 bytes: 5c75cef01a960df74cb6b49b9e38e6b5
    Actual first 16 bytes: 5c75cef01a960df74cb6b49b9e38e6b5
    Match: true

    Test 2
    Expected first 16 bytes: d1daa78615f287e6a1c8b120d7062a49
    Actual first 16 bytes: d1daa78615f287e6a1c8b120d7062a49
    Match: true

    PW->Key: d1daa78615f287e6a1c8b120d7062a493f98d203e6be49a6adf4fa574b6e64eedf37
    Encryption key: d1daa78615f287e6a1c8b120d7062a49
    Authentication key: 3f98d203e6be49a6adf4fa574b6e64ee
    PW Verify Code: df37
