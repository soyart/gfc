package cli

import (
	"fmt"
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

func (c *cmdRSA) key() ([]byte, error) {
	if c.DecryptFlag {
		switch {
		case c.PriKey == "" && c.PriKeyFilename == "":
			return nil, errors.New("missing private key for RSA decryption")

		case c.PriKey != "":
			return []byte(c.PriKey), nil

		default:
			key, err := os.ReadFile(c.PriKeyFilename)
			if err != nil {
				return nil, errors.Wrap(err, "failed to read RSA private key file")
			}

			return key, nil
		}
	}

	switch {
	case c.PubKey == "" && c.PubkeyFilename == "":
		return nil, errors.New("missing public key for RSA encryption")

	case c.PubKey == "":
		return []byte(c.PubKey), nil

	default:
		key, err := os.ReadFile(c.PubkeyFilename)
		if err != nil {
			return nil, errors.Wrap(err, "failed to read RSA public key file")
		}

		return key, nil
	}
}

//nolint:wrapcheck
func (c *cmdRSA) crypt(
	mode gfc.AlgoMode,
	buf gfc.Buffer,
	key []byte,
	decrypt bool,
) (
	gfc.Buffer,
	error,
) {
	if mode != gfc.ModeRsaOEAP {
		panic(fmt.Sprintf("invalid RSA mode %d", mode))
	}

	if decrypt {
		return gfc.DecryptRSA(buf, key)
	}

	return gfc.EncryptRSA(buf, key)
}
