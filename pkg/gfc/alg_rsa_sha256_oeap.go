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

func EncryptRSA(plaintext Buffer, pubKey []byte) (Buffer, error) {
	block, _ := pem.Decode([]byte(pubKey))

	var pub *rsa.PublicKey

	// PKIX is PKCS1 with certificates/identity metadata
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// PKCS1 does not have certificates
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

	ciphertext, err := rsa.EncryptOAEP(sha512.New(), rand.Reader, pub, plaintextBytes, nil)
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

	plaintext, err := rsa.DecryptOAEP(sha512.New(), rand.Reader, pri, ciphertextBytes, nil)
	if err != nil {
		return nil, errors.Wrap(err, ErrDecryptRSA.Error())
	}

	return bytes.NewBuffer(plaintext), nil
}
