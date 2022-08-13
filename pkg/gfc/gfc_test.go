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
		key := make([]byte, keyFileLen)
		_, err := rand.Read(key)
		if err != nil {
			t.Fatalf("error filling random key bytes: %s", err.Error())
		}
		testSymmestricCryptograhy(t, "AES256-GCM", EncryptGCM, DecryptGCM, plaintext, key)
		testSymmestricCryptograhy(t, "AES256-CTR", EncryptCTR, DecryptCTR, plaintext, key)
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

		testAsymmestricCryptograhy(t, "RSA256-OEAP", EncryptRSA, DecryptRSA, plaintext, priPEM, pubPEM)
	})
}

func testSymmestricCryptograhy(
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

func testAsymmestricCryptograhy(
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
