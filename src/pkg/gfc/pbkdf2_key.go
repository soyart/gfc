package gfc

// key.go is for encryption key derivation.
// This file defines KeyFile struct and its methods,

import (
	"crypto/rand"
	"crypto/sha256"
	"os"

	"github.com/pkg/errors"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/term"
)

const (
	pbkdf2Rounds        int = 1 << 20 // PBKDF2 pbkdf2Rounds
	lenPBKDF2Salt       int = 32
	aes256BitKeyFileLen int = 32
)

func getPass() []byte {
	os.Stdout.Write([]byte("Passphrase (will not echo)\n"))
	passphrase, _ := term.ReadPassword(0)
	return passphrase
}

func generateSaltPBKDF2(salt []byte) []byte {
	if salt == nil {
		salt = make([]byte, lenPBKDF2Salt)
		rand.Read(salt)
	}
	return salt
}

/* Derive 256-bit key and salt using PBKDF2 */
func generateKeySaltPBKDF2(passphrase, salt []byte) ([]byte, []byte) {
	salt = generateSaltPBKDF2(salt)
	return pbkdf2.Key(passphrase, salt, pbkdf2Rounds, lenPBKDF2Salt, sha256.New), salt
}

// If symmetric key is nil, getPass() is called to get passphrase from user.
// If salt is nil, new salt is created.
func keySaltPBKDF2(symmetricKey, salt []byte) ([]byte, []byte, error) {
	if symmetricKey != nil {
		keyLen := len(symmetricKey)
		if keyLen != aes256BitKeyFileLen {
			return nil, nil, errors.Wrapf(ErrInvalidaes256BitKeyFileLen, "keyfile length is %d", keyLen)
		}
		// If salt is new (encryption), generate new salt
		salt = generateSaltPBKDF2(salt)
		return symmetricKey, salt, nil
	}
	// Passphrase
	symmetricKey, salt = generateKeySaltPBKDF2(getPass(), salt)
	return symmetricKey, salt, nil
}
