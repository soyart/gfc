package gfc

// This file provides default encryption mode for gfc.
// This mode is chosen because it has message authentication
// built-in and because it is generally faster.
// For very large files, you may want to use CTR.
// See https://golang.org/src/crypto/cipher/gcm.go

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
)

const (
	lenNonce int = 12 // use 96-bit nonce
)

func EncryptGCM(plaintext Buffer, aesKey []byte) (ciphertext Buffer, err error) {
	key, salt := getKeySalt(aesKey, nil)
	block, err := aes.NewCipher(key)
	if err != nil {
		err = EGCMNEWCIPHER
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		err = EGCMNEWGCM
		return
	}

	nonce := make([]byte, lenNonce)
	rand.Read(nonce)

	var plaintextBytes []byte
	switch plaintext := plaintext.(type) {
	case *bytes.Buffer:
		plaintextBytes = plaintext.Bytes()
	}

	// To encrypt, we use Seal(dst, nonce, plaintext, data []byte) []byte
	ciphertext = new(bytes.Buffer)
	ciphertext.Write(gcm.Seal(nil, nonce, plaintextBytes, nil))
	ciphertext.Write(append(nonce, salt...))

	// salt is appended last, hence output format is
	// "ciphertext + nonce + salt".
	// This allow us to easily extract salt
	// for key derivation later when decrypting.

	return
}

func DecryptGCM(ciphertext Buffer, aesKey []byte) (plaintext Buffer, err error) {

	var ciphertextBytes []byte
	switch ciphertext := ciphertext.(type) {
	case *bytes.Buffer:
		ciphertextBytes = ciphertext.Bytes()
	}

	lenData := len(ciphertextBytes)
	salt := ciphertextBytes[lenData-lenSalt:]
	key, _ := getKeySalt(aesKey, salt)
	nonce := ciphertextBytes[lenData-lenNonce-lenSalt : lenData-lenSalt]
	ciphertextBytes = ciphertextBytes[:lenData-lenNonce-lenSalt]

	block, err := aes.NewCipher(key)
	if err != nil {
		err = EGCMNEWCIPHER
		return
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		err = EGCMNEWGCM
		return
	}

	/* To decrypt, we use Open(dst, nonce, ciphertext, ciphertext []byte) ([]byte, error) */
	plaintextRaw, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		err = EGCMOPEN
		return
	}
	plaintext = bytes.NewBuffer(plaintextRaw)
	return
}
