package gfc

// This file is used to asymmetrically encrypt AES keys
// so that we can use public key cryptography with long plaintext messages

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"os"
)

var (
	hash = sha512.New()
	salt = rand.Reader
)

func EncryptRSA(plaintext Buffer, pubKey []byte) (ciphertext Buffer, r int) {
	block, _ := pem.Decode([]byte(pubKey))
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		os.Stderr.Write([]byte("Failed to parse public key\n"))
		r = ERSAPARSEPUB
		return
	}
	pub := pubInterface.(*rsa.PublicKey)

	var plaintextBytes []byte
	switch plaintext := plaintext.(type) {
	case *bytes.Buffer:
		plaintextBytes = plaintext.Bytes()
	}

	ciphertextRaw, err := rsa.EncryptOAEP(hash, salt, pub, plaintextBytes, nil)
	if err != nil {
		os.Stderr.Write([]byte("Failed to encrypt string\n"))
		r = ERSAENCR
		return
	}
	ciphertext = bytes.NewBuffer(ciphertextRaw)
	return
}

func DecryptRSA(ciphertext Buffer, priKey []byte) (plaintext Buffer, r int) {
	block, _ := pem.Decode([]byte(priKey))
	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		os.Stderr.Write([]byte("Failed to parse private key\n"))
		r = ERSAPARSEPRI
		return
	}

	var ciphertextBytes []byte
	switch ciphertext := ciphertext.(type) {
	case *bytes.Buffer:
		ciphertextBytes = ciphertext.Bytes()
	}

	plaintextRaw, err := rsa.DecryptOAEP(hash, salt, pri, ciphertextBytes, nil)
	if err != nil {
		os.Stderr.Write([]byte("Failed to decrypt string\n"))
		r = ERSADECR
		return
	}
	plaintext = bytes.NewBuffer(plaintextRaw)
	return
}
