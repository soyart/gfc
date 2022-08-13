package gfc

import "golang.org/x/crypto/chacha20poly1305"

func EncryptChaCha20Poly1305(plaintext Buffer, key []byte) (Buffer, error) {
	return EncryptChaCha20(
		chacha20poly1305.New,
		chacha20poly1305.NonceSize,
		plaintext,
		key,
	)
}

func DecryptChaCha20Poly1305(ciphertext Buffer, key []byte) (Buffer, error) {
	return DecryptChaCha20(
		chacha20poly1305.New,
		chacha20poly1305.NonceSize,
		ciphertext,
		key,
	)
}
