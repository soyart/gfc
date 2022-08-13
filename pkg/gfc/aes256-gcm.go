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

	"github.com/pkg/errors"
)

func EncryptGCM(plaintext Buffer, aesKey []byte) (Buffer, error) {
	key, salt, err := keySaltPBKDF2(aesKey, nil)
	if err != nil {
		err = errors.Wrap(err, ErrPBKDF2KeySalt.Error())
		return nil, errors.Wrap(err, "AES256-GCM encryption")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, ErrNewCipherGCM.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, ErrNewGCM.Error())
	}

	return marshalGfcSymmAEAD(gcm, plaintext, lenNonceGCM, salt)
}

func DecryptGCM(ciphertext Buffer, aesKey []byte) (Buffer, error) {
	ciphertextBytes, key, nonce, err := unmarshalGfcSymmAEAD(ciphertext, aesKey, lenNonceGCM)
	if err != nil {
		return nil, errors.Wrap(err, ErrUnmarshalSymmAEAD.Error())
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, ErrNewCipherGCM.Error())
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errors.Wrap(err, ErrNewGCM.Error())
	}
	/* To decrypt, we use Open(dst, nonce, ciphertext, ciphertext []byte) ([]byte, error) */
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return nil, errors.Wrap(err, ErrOpenGCM.Error())
	}
	return bytes.NewBuffer(plaintext), nil
}