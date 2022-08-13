package gfc

import (
	"bytes"
	"crypto/rand"
	"os"
	"testing"
)

func TestCryptography(t *testing.T) {
	plaintext := []byte("this is my plaintext")

	t.Run("testAES", func(t *testing.T) {
		key := make([]byte, aes256BitKeyFileLen)
		_, err := rand.Read(key)
		if err != nil {
			t.Fatalf("error filling random key bytes: %s", err.Error())
		}
		testSymmetricCryptograhy(t, "AES256-GCM", EncryptGCM, DecryptGCM, plaintext, key)
		testSymmetricCryptograhy(t, "AES256-CTR", EncryptCTR, DecryptCTR, plaintext, key)
	})
	t.Run("testRSA", func(t *testing.T) {
		pubFile := "./assets/files/pub.pem"
		priFile := "./assets/files/pri.pem"

		pubPEM, err := os.ReadFile(pubFile)
		if err != nil {
			t.Logf("failed to read public key file from %s: %s", pubFile, err.Error())
			t.SkipNow()
		}
		priPEM, err := os.ReadFile(priFile)
		if err != nil {
			t.Logf("failed to read public key file from %s: %s", priFile, err.Error())
			t.SkipNow()
		}

		testAsymmetricCryptograhy(t, "RSA256-OEAP", EncryptRSA, DecryptRSA, plaintext, priPEM, pubPEM)
	})
	t.Run("testXChaCha20Poly1305", func(t *testing.T) {
		key := make([]byte, aes256BitKeyFileLen)
		_, err := rand.Read(key)
		if err != nil {
			t.Fatalf("error filling random key bytes: %s", err.Error())
		}
		testSymmetricCryptograhy(t, "XChaCha20Poly1305", EncryptXChaCha20Poly1305, DecryptXChaCha20Poly1305, plaintext, key)
		testSymmetricCryptograhy(t, "ChaCha20Poly1305", EncryptChaCha20Poly1305, DecryptChaCha20Poly1305, plaintext, key)
	})
}

func testSymmetricCryptograhy(
	t *testing.T,
	name string,
	encryptFunc func(Buffer, []byte) (Buffer, error),
	decryptFunc func(Buffer, []byte) (Buffer, error),
	plaintext []byte,
	key []byte,
) {
	ciphertextBuf, err := encryptFunc(bytes.NewBuffer(plaintext), key)
	if err != nil {
		t.Fatalf("error encrypting with %s: %s", name, err.Error())
	}
	plaintextBuf, err := decryptFunc(ciphertextBuf, key)
	if err != nil {
		t.Fatalf("error decrypting with %s: %s", name, err.Error())
	}

	if !bytes.Equal(plaintextBuf.(*bytes.Buffer).Bytes(), plaintext) {
		t.Fatal("output does not match")
	}
}

func testAsymmetricCryptograhy(
	t *testing.T,
	name string,
	encryptFunc func(Buffer, []byte) (Buffer, error),
	decryptFunc func(Buffer, []byte) (Buffer, error),
	plaintext []byte,
	priKey []byte,
	pubKey []byte,
) {
	ciphertextBuf, err := encryptFunc(bytes.NewBuffer(plaintext), pubKey)
	if err != nil {
		t.Fatalf("error encrypting with %s: %s", name, err.Error())
	}
	plaintextBuf, err := decryptFunc(ciphertextBuf, priKey)
	if err != nil {
		t.Fatalf("error decrypting with %s: %s", name, err.Error())
	}

	if !bytes.Equal(plaintextBuf.(*bytes.Buffer).Bytes(), plaintext) {
		t.Fatal("output does not match")
	}
}
