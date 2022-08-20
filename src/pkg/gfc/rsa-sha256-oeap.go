package gfc

// This file provides RSA-OEAP encryption for gfc.

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"

	"github.com/pkg/errors"
)

var (
	hash = sha512.New()
	salt = rand.Reader
)

func EncryptRSA(plaintext Buffer, pubKey []byte) (Buffer, error) {
	block, _ := pem.Decode([]byte(pubKey))
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	var pub *rsa.PublicKey
	if err != nil {
		pub, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, errors.Wrap(err, ErrParsePubRSA.Error())
		}
	} else {
		pub = pubInterface.(*rsa.PublicKey)
	}

	var plaintextBytes []byte
	switch plaintext := plaintext.(type) {
	case *bytes.Buffer:
		plaintextBytes = plaintext.Bytes()
	}

	ciphertext, err := rsa.EncryptOAEP(hash, salt, pub, plaintextBytes, nil)
	if err != nil {
		return nil, errors.Wrap(err, ErrEncryptRSA.Error())
	}
	return bytes.NewBuffer(ciphertext), nil
}

func DecryptRSA(ciphertext Buffer, priKey []byte) (Buffer, error) {
	block, _ := pem.Decode([]byte(priKey))
	pri, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, ErrParsePriRSA.Error())
	}

	var ciphertextBytes []byte
	switch ciphertext := ciphertext.(type) {
	case *bytes.Buffer:
		ciphertextBytes = ciphertext.Bytes()
	}

	plaintext, err := rsa.DecryptOAEP(hash, salt, pri, ciphertextBytes, nil)
	if err != nil {
		return nil, errors.Wrap(err, ErrDecryptRSA.Error())
	}
	return bytes.NewBuffer(plaintext), nil
}
