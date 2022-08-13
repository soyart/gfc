package gfc

import (
	"golang.org/x/crypto/chacha20poly1305"
)

func EncryptXChaCha20Poly1305(plaintext Buffer, key []byte) (Buffer, error) {
	return EncryptChaCha20(
		chacha20poly1305.NewX,
		chacha20poly1305.NonceSizeX,
		plaintext,
		key,
	)
}

func DecryptXChaCha20Poly1305(ciphertext Buffer, key []byte) (Buffer, error) {
	return DecryptChaCha20(
		chacha20poly1305.NewX,
		chacha20poly1305.NonceSizeX,
		ciphertext,
		key,
	)
}
