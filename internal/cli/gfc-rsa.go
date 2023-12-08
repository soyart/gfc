package cli

import (
	"os"

	"github.com/pkg/errors"

	"github.com/soyart/gfc/pkg/gfc"
)

type cmdRSA struct {
	PubKey         string `arg:"env:PUB" placeholder:"PUB" help:"Public key string - e.g.: 'PUB=$(< id_rsa.pub) gfc rsa ...'"`
	PriKey         string `arg:"env:PRI" placeholder:"PRI" help:"Private key string - e.g.: 'PRI=$(< id_rsa) gfc rsa -d ...'"`
	PubkeyFilename string `arg:"-p,--public-key" placeholder:"PUBFILE" help:"Public key filename"`
	PriKeyFilename string `arg:"-P,--private-key" placeholder:"PRIFILE" help:"Private key filename"`

	baseCommand
}

// rsaCommand only supports 1 RSA mode for now (OEAP)
func (c *cmdRSA) algoMode() (gfc.AlgoMode, error) {
	return gfc.ModeRsaOEAP, nil
}

// rsaCommand will give key strings priority over key filenames
func (c *cmdRSA) key() ([]byte, error) {
	if c.DecryptFlag {
		if c.PriKey == "" {
			if c.PriKeyFilename != "" {
				return os.ReadFile(c.PriKeyFilename)
			}

			return nil, errors.New("missing private key for RSA decryption")
		}

		return []byte(c.PriKey), nil
	}

	// RSA Encryption
	if c.PubKey == "" {
		if c.PubkeyFilename != "" {
			return os.ReadFile(c.PubkeyFilename)
		}

		return nil, errors.New("missing public key for RSA encryption")
	}

	return []byte(c.PubKey), nil
}

func (c *cmdRSA) crypt(
	mode gfc.AlgoMode,
	buf gfc.Buffer,
	key []byte,
	decrypt bool,
) (
	gfc.Buffer,
	error,
) {
	switch mode {
	case gfc.ModeRsaOEAP:
		if decrypt {
			return gfc.DecryptRSA(buf, key)
		}

		return gfc.EncryptRSA(buf, key)
	}

	return nil, errors.New("invalid RSA mode (should not happen)")
}
