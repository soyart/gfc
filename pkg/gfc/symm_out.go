package gfc

import (
	"bytes"
	"fmt"

	"github.com/pkg/errors"
)

// formatOutputGfcSymm serializes the output for all symmetric key encryption by gfc
func formatOutputGfcSymm(
	ciphertext []byte,
	nonce []byte,
	salt []byte,
) (
	Buffer,
	error,
) {
	lenNonce := len(nonce)
	lenSalt := len(salt)

	buf := bytes.NewBuffer(ciphertext)
	n, err := buf.Write(nonce)
	if err != nil {
		return nil, errors.Wrap(err, "failed to append nonce to symmetric encryption output")
	}

	if n != lenNonce {
		return nil, fmt.Errorf("unexpected nonce bytes written - expecting %d, got %d", lenNonce, n)
	}

	n, err = buf.Write(salt)
	if err != nil {
		return nil, errors.Wrap(err, "failed to append salt to symmetric encryption output")
	}

	if n != lenSalt {
		return nil, fmt.Errorf("unexpected salt bytes written - expecting %d, got %d", lenSalt, n)
	}

	return buf, nil
}

// decodeOutputGfcSymm unmarshals gfc symmetric key encryption output into message length, ciphertext, key, and nonce
func decodeOutputGfcSymm(
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
