package gfc

// key.go is for encryption key derivation.
// This file defines KeyFile struct and its methods,

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
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

// genKeySaltPBKDF2 generates key-salt pair from k and salt.
// If k is nil, a password prompt will be shown to read input passphrase to k.
// If salt is nil, a new salt is generated
func genKeySaltPBKDF2(k, salt []byte) ([]byte, []byte, error) {
	l := len(k)
	if l != 0 && l != aes256BitKeyFileLen {
		return nil, nil, errors.Wrapf(ErrInvalidaes256BitKeyFileLen, "keyfile length is %d", l)
	}

	salt = getSalt(salt)

	if l == 0 {
		var err error
		k, err = passphrasePrompt()
		if err != nil {
			return nil, nil, err
		}

		k = pbkdf2.Key(k, salt, pbkdf2Rounds, lenPBKDF2Salt, sha256.New)
	}

	return k, salt, nil
}

func passphrasePrompt() ([]byte, error) {
	os.Stdout.WriteString("Passphrase (will not echo)\n")
	passphrase, err := term.ReadPassword(0)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get passphrase from tty")
	}

	return passphrase, nil
}

// getSalt returns a new random salt if salt is nil,
// or echoing the given salt if it's ok to use.
func getSalt(salt []byte) []byte {
	if salt != nil {
		if lenSalt := len(salt); lenSalt != lenPBKDF2Salt {
			panic(fmt.Sprintf("bad salt len - expecting %d, got %d", lenPBKDF2Salt, lenSalt))
		}

		return salt
	}

	salt = make([]byte, lenPBKDF2Salt)
	n, err := rand.Read(salt)
	if err != nil {
		panic("failed to read random salt: " + err.Error())
	}

	if n != lenPBKDF2Salt {
		panic(fmt.Sprintf("unexpected random salt len - expecting %d, got %d", lenPBKDF2Salt, n))
	}

	return salt
}
