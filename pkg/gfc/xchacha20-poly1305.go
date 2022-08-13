package gfc

import (
	"bytes"
	"crypto/rand"

	"github.com/pkg/errors"
	"golang.org/x/crypto/chacha20poly1305"
)

func EncryptXChaCha20Poly1305(plaintext Buffer, key []byte) (Buffer, error) {
	key, salt, err := keySaltPBKDF2(key, nil)
	if err != nil {
		err = errors.Wrap(err, ErrPBKDF2KeySalt.Error())
		return nil, errors.Wrap(err, "ChaCha20Poly1305 encryption")
	}
	block, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, errors.Wrap(err, ErrNewCipherXChaCha20Poly1305.Error())
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	rand.Read(nonce)
	ciphertext := new(bytes.Buffer)
	ciphertext.Write(block.Seal(nil, nonce, plaintext.Bytes(), nil))
	ciphertext.Write(append(nonce, salt...))

	return ciphertext, nil
}

func DecryptXChaCha20Poly1305(ciphertext Buffer, key []byte) (Buffer, error) {
	var ciphertextBytes []byte
	switch ciphertext := ciphertext.(type) {
	case *bytes.Buffer:
		ciphertextBytes = ciphertext.Bytes()
	}

	lenGfcCiphertext := len(ciphertextBytes)
	saltStart := lenGfcCiphertext - lenPBKDF2Salt
	salt := ciphertextBytes[saltStart:]
	key, _, err := keySaltPBKDF2(key, salt)
	if err != nil {
		err = errors.Wrap(err, ErrPBKDF2KeySalt.Error())
		return nil, errors.Wrap(err, "ChaCha20Poly1305 decryption")
	}
	nonceStart := saltStart - chacha20poly1305.NonceSizeX
	nonce := ciphertextBytes[nonceStart:saltStart]
	ciphertextBytes = ciphertextBytes[:nonceStart]

	block, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, errors.Wrap(err, ErrNewCipherXChaCha20Poly1305.Error())
	}
	plaintextRaw, err := block.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return nil, errors.Wrap(err, ErrOpenXChaCha20Poly1305.Error())
	}

	return bytes.NewBuffer(plaintextRaw), nil
}
