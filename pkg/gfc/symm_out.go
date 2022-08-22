package gfc

import (
	"bytes"

	"github.com/pkg/errors"
)

// marshalSymmOut marshals the output for all symmetric key encryption by gfc
func marshalSymmOut(
	ciphertext []byte,
	nonce []byte,
	salt []byte,
) (
	Buffer,
	error,
) {
	buf := bytes.NewBuffer(ciphertext)
	buf.Write(nonce)
	buf.Write(salt)
	return buf, nil
}

// unmarshalSymmOut unmarshals gfc symmetric key encryption output into message length, ciphertext, key, and nonce
func unmarshalSymmOut(
	ciphertext Buffer,
	key []byte,
	nonceSize int,
) (
	int, // lenMsg or nonceStart
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
		return 0, nil, nil, nil, errors.Wrap(err, ErrPBKDF2KeySalt.Error())
	}

	nonceStart := saltStart - nonceSize
	nonce := ciphertextBytes[nonceStart:saltStart]
	ciphertextBytes = ciphertextBytes[:nonceStart]

	return nonceStart, ciphertextBytes, key, nonce, nil
}
