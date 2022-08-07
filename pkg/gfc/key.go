package gfc

// key.go is for encryption key derivation.
// This file defines KeyFile struct and its methods,

import (
	"crypto/rand"
	"crypto/sha256"
	"os"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

const (
	rounds     int = 1 << 20 // PBKDF2 rounds
	lenSalt    int = 32
	keyFileLen int = 32
)

func getPass() []byte {
	os.Stdout.Write([]byte("Passphrase (will not echo)\n"))
	passphrase, _ := term.ReadPassword(0)
	return passphrase
}

/* Derive 256-bit key and salt using PBKDF2 */
func genKeySalt(passphrase []byte, salt []byte) ([]byte, []byte) {
	if salt == nil {
		salt = make([]byte, lenSalt)
		rand.Read(salt)
	}
	return pbkdf2.Key(passphrase, salt, rounds, lenSalt, sha256.New), salt
}

// If AES key is nil, getPass() is called to get passphrase from user.
// If salt is nil, new salt is created.
func getKeySalt(aesKey []byte, salt []byte) ([]byte, []byte, error) {
	if aesKey == nil {
		// Passphrase
		key, salt := genKeySalt(getPass(), salt)
		return key, salt, nil

	} else {
		keyLen := len(aesKey)
		if keyLen != keyFileLen {
			return nil, nil, ErrInvalidKeyfileLen
		}
		// If salt is new (encryption), generate new salt
		if salt == nil {
			salt = make([]byte, lenSalt)
			rand.Read(salt)
		}
		return aesKey, salt, nil
	}
}
