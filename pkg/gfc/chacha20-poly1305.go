package gfc

// This file provides XChaCha20-Poly1035 and ChaCha20-Poly1305 encryption for gfc.
// If you are using gfc-cli, then the default mode is going to be XChaCha20.
// In gfc, the XChaCha20/ChaCha20 shares the same output format as AES256-GCM/CTR.

import "golang.org/x/crypto/chacha20poly1305"

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
