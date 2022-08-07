package gfc

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestGCM(t *testing.T) {
	key := make([]byte, keyFileLen)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("error filling key bytes: %s", err.Error())
	}
	plaintext := []byte("this_is_my_plaintext")
	ciphertextBuf, err := EncryptGCM(bytes.NewBuffer(plaintext), key)
	if err != nil {
		t.Fatalf("error encrypting with CTR: %s", err)
	}
	plaintextBuf, err := DecryptGCM(ciphertextBuf, key)
	if err != nil {
		t.Fatalf("error encrypting with CTR: %s", err)
	}

	if !bytes.Equal(plaintextBuf.(*bytes.Buffer).Bytes(), plaintext) {
		t.Fatal("output does not match")
	}
}
