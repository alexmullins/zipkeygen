 Program tests the key derivation of golang packages and compares the results
 to those of Dr. Brian Gladman's WinZip AES crypto functions.
 His website is at: http:www.gladman.me.uk/cryptography_technology/fileencrypt/

 WinZip AES specifies
  1. Encrpytion-Decryption w/ AES-CTR (128, 192, 256)
  2. KeyGen with PBKDF2-HMAC-SHA1 (1000 iteration count)that generate 160 bit key
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
  6. Total key size for PBKDF2 is AES Key Size + Auth Key Size + 2 bytes
      a. AES 128 = 16 + 16 + 2 = 34 bytes of key material
      b. AES 192 = 24 + 24 + 2 = 50 bytes of key material
      c. AES 256 = 32 + 32 + 2 = 66 bytes of key material