package gfc

import (
	"bytes"
	"crypto/cipher"
	"crypto/rand"

	"github.com/pkg/errors"
)

// marshalSymmOut generates random nonce of size nonceSize
// and marshals the output for all symmetric key encryption by gfc
func marshalSymmOut(
	c cipher.AEAD,
	plaintext Buffer,
	nonceSize int,
	salt []byte,
) (
	Buffer,
	error,
) {
	nonce := make([]byte, nonceSize)
	rand.Read(nonce)

	ciphertext := new(bytes.Buffer)
	ciphertext.Write(c.Seal(nil, nonce, plaintext.Bytes(), nil))
	// Append AEAD nonce and PBKDF2 salt
	ciphertext.Write(nonce)
	ciphertext.Write(salt)

	return ciphertext, nil
}

// unmarshalSymmOut unmarshals gfc symmetric key encryption output into ciphertext, key, and nonce
func unmarshalSymmOut(
	ciphertext Buffer,
	key []byte,
	nonceSize int,
) (
	[]byte, // Ciphertext
	[]byte, // Key
	[]byte, // Nonce
	error,
) {
	ciphertextBytes := ciphertext.Bytes()
	lenGfcCiphertext := ciphertext.Len()

	saltStart := lenGfcCiphertext - lenPBKDF2Salt
	salt := ciphertextBytes[saltStart:]

	key, _, err := keySaltPBKDF2(key, salt)
	if err != nil {
		return nil, nil, nil, errors.Wrap(err, ErrPBKDF2KeySalt.Error())
	}

	nonceStart := saltStart - nonceSize
	nonce := ciphertextBytes[nonceStart:saltStart]
	ciphertextBytes = ciphertextBytes[:nonceStart]

	return ciphertextBytes, key, nonce, nil
}
