package gfc

// This file provides (X)ChaCha20-Poly1305 encryption for gfc.

import (
	"bytes"
	"crypto/cipher"

	"github.com/pkg/errors"
	"golang.org/x/crypto/chacha20poly1305"
)

func EncryptFamilyChaCha20(
	newCipherFunc func([]byte) (cipher.AEAD, error),
	nonceSize int,
	plaintext Buffer,
	key []byte,
) (
	Buffer,
	error,
) {
	key, salt, err := keySaltPBKDF2(key, nil)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get key and salt with PBKDF2")
	}
	block, err := newCipherFunc(key)
	if err != nil {
		return nil, errors.Wrap(err, ErrNewCipherXChaCha20Poly1305.Error())
	}

	return marshalSymmOut(block, plaintext, nonceSize, salt)
}

func DecryptFamilyChaCha20(
	newCipherFunc func([]byte) (cipher.AEAD, error),
	nonceSize int,
	ciphertext Buffer,
	key []byte,
) (
	Buffer,
	error,
) {
	ciphertextBytes, key, nonce, err := unmarshalSymmOut(ciphertext, key, nonceSize)
	if err != nil {
		return nil, errors.Wrap(err, "failed to unmarshal gfc symmAEAD format")
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

func EncryptXChaCha20Poly1305(plaintext Buffer, key []byte) (Buffer, error) {
	return EncryptFamilyChaCha20(
		chacha20poly1305.NewX,
		chacha20poly1305.NonceSizeX,
		plaintext,
		key,
	)
}

func DecryptXChaCha20Poly1305(ciphertext Buffer, key []byte) (Buffer, error) {
	return DecryptFamilyChaCha20(
		chacha20poly1305.NewX,
		chacha20poly1305.NonceSizeX,
		ciphertext,
		key,
	)
}

func EncryptChaCha20Poly1305(plaintext Buffer, key []byte) (Buffer, error) {
	return EncryptFamilyChaCha20(
		chacha20poly1305.New,
		chacha20poly1305.NonceSize,
		plaintext,
		key,
	)
}

func DecryptChaCha20Poly1305(ciphertext Buffer, key []byte) (Buffer, error) {
	return DecryptFamilyChaCha20(
		chacha20poly1305.New,
		chacha20poly1305.NonceSize,
		ciphertext,
		key,
	)
}
