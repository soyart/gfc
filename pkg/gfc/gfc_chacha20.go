package gfc

import (
	"bytes"
	"crypto/cipher"

	"github.com/pkg/errors"
)

// EncryptChaCha20 is wrapped by both EncryptXChaCha20Poly1305 and EncryptChaChaPoly1305
func EncryptChaCha20(
	newCipherFunc func([]byte) (cipher.AEAD, error),
	nonceSize int,
	plaintext Buffer,
	key []byte,
) (Buffer, error) {
	key, salt, err := keySaltPBKDF2(key, nil)
	if err != nil {
		err = errors.Wrap(err, ErrPBKDF2KeySalt.Error())
		return nil, errors.Wrap(err, "ChaCha20Poly1305 encryption")
	}
	block, err := newCipherFunc(key)
	if err != nil {
		return nil, errors.Wrap(err, ErrNewCipherXChaCha20Poly1305.Error())
	}

	return marshalGfcSymmAEAD(block, plaintext, nonceSize, salt)
}

// DecryptChaCha20 is wrapped by both DecryptXChaCha20Poly1305 and DecryptChaChaPoly1305
func DecryptChaCha20(
	newCipherFunc func([]byte) (cipher.AEAD, error),
	nonceSize int,
	ciphertext Buffer,
	key []byte,
) (Buffer, error) {
	ciphertextBytes, key, nonce, err := unmarshalGfcSymmAEAD(ciphertext, key, nonceSize)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal")
	}
	block, err := newCipherFunc(key)
	if err != nil {
		return nil, errors.Wrap(err, ErrNewCipherXChaCha20Poly1305.Error())
	}
	plaintext, err := block.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return nil, errors.Wrap(err, ErrOpenXChaCha20Poly1305.Error())
	}

	return bytes.NewBuffer(plaintext), nil
}
