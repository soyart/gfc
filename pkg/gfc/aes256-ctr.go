package gfc

// This file provides AES256-CTR encryption for gfc.
// CTR converts a block cipher into a stream cipher by
// repeatedly encrypting an incrementing counter and
// xoring the resulting stream of data with the input.
// In gfc, this mode does not authenticate decrypted message
// so I recommend you use GCM (default mode for gfc).
// See https://golang.org/src/crypto/cipher/ctr.go

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/pkg/errors"
)

const blockSizeAES256CTR = 16

func EncryptCTR(plaintext Buffer, aesKey []byte) (Buffer, error) {
	key, salt, err := keySaltPBKDF2(aesKey, nil)
	if err != nil {
		err = errors.Wrap(err, ErrPBKDF2KeySalt.Error())
		return nil, errors.Wrap(err, "AES256-CTR encryption")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, ErrNewCipherCTR.Error())
	}

	// blockSize is 16
	iv := make([]byte, blockSizeAES256CTR)
	rand.Read(iv)

	stream := cipher.NewCTR(block, iv)
	ciphertext := new(bytes.Buffer)

	// We will be using a byte buffer of size 1024
	buf := make([]byte, 1024)
	for {
		// Read n bytes from plaintext to buf
		n, err := plaintext.Read(buf)
		if n > 0 {
			stream.XORKeyStream(buf, buf[:n])
			// Write buf[:n] to ciphertext
			ciphertext.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.Wrap(err, ErrReadCTR.Error())
		}
	}

	return marshalSymmOut(
		ciphertext.Bytes(),
		iv,
		salt,
	)
}

func DecryptCTR(ciphertext Buffer, aesKey []byte) (Buffer, error) {
	lenMsg, _, key, iv, err := unmarshalSymmOut(ciphertext, aesKey, blockSizeAES256CTR)
	if err != nil {
		return nil, errors.Wrap(err, ErrUnmarshalSymmAEAD.Error())
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.Wrap(err, ErrNewCipherCTR.Error())
	}
	stream := cipher.NewCTR(block, iv)
	buf := make([]byte, 1024)
	plaintext := new(bytes.Buffer)
	for {
		n, err := ciphertext.Read(buf)
		if n > 0 {
			if n > lenMsg {
				n = lenMsg
			}
			lenMsg -= n
			stream.XORKeyStream(buf, buf[:n])
			plaintext.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, errors.Wrap(err, ErrReadCTR.Error())
		}
	}

	return plaintext, nil
}
