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
)

func CTR_encrypt(plaintext Buffer, aesKey []byte) (ciphertext Buffer, r int) {

	key, salt := getKeySalt(aesKey, nil)
	block, err := aes.NewCipher(key)
	if err != nil {
		r = ECTRNEWCIPHER
		return
	}

	iv := make([]byte, block.BlockSize())
	rand.Read(iv)

	stream := cipher.NewCTR(block, iv)
	ciphertext = new(bytes.Buffer)
	buf := make([]byte, 1024)
	for {
		n, err := plaintext.Read(buf)
		if n > 0 {
			stream.XORKeyStream(buf, buf[:n])
			ciphertext.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			r = ECTRREAD
			return
		}
	}

	ciphertext.Write(append(iv, salt...))
	return
}

func CTR_decrypt(ciphertext Buffer, aesKey []byte) (plaintext Buffer, r int) {

	var data []byte
	switch ciphertext := ciphertext.(type) {
	case *bytes.Buffer:
		data = ciphertext.Bytes()
	}
	lenData := len(data)

	salt := data[lenData-lenSalt:]
	key, _ := getKeySalt(aesKey, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		r = ECTRNEWCIPHER
		return
	}

	lenIV := block.BlockSize()
	iv := data[lenData-lenIV-lenSalt : lenData-lenSalt]
	lenMsg := lenData - lenIV - lenSalt

	stream := cipher.NewCTR(block, iv)
	buf := make([]byte, 1024)
	plaintext = new(bytes.Buffer)
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
			r = ECTRREAD
			return
		}
	}

	return
}
