package cli

import (
	"os"

	"github.com/pkg/errors"

	"github.com/artnoi43/gfc/pkg/gfc"
)

type rsaCommand struct {
	baseCryptFlags
	PubKey         string `arg:"env:PUB" placeholder:"PUB" help:"Public key string - e.g.: 'PUB=$(< id_rsa.pub) gfc rsa ...'"`
	PriKey         string `arg:"env:PRI" placeholder:"PRI" help:"Private key string - e.g.: 'PRI=$(< id_rsa) gfc rsa -d ...'"`
	PubkeyFilename string `arg:"-p,--public-key" placeholder:"PUBFILE" help:"Public key filename"`
	PriKeyFilename string `arg:"-P,--private-key" placeholder:"PRIFILE" help:"Private key filename"`
}

// rsaCommand only supports 1 RSA mode for now (OEAP)
func (cmd *rsaCommand) algoMode() (gfc.AlgoMode, error) {
	return gfc.RSA_OEAP, nil
}

// Unlike with AES, gfc will not be reading either of the keypair from files.
// Instead, users will provide the keys as string
func (cmd *rsaCommand) key() ([]byte, error) {
	if cmd.DecryptFlag {
		if cmd.PriKey == "" {
			if cmd.PriKeyFilename != "" {
				return os.ReadFile(cmd.PriKeyFilename)
			}
			return nil, errors.New("missing private key for RSA decryption")
		}
		return []byte(cmd.PriKey), nil
	}
	// RSA Encryption
	if cmd.PubKey == "" {
		if cmd.PubkeyFilename != "" {
			return os.ReadFile(cmd.PubkeyFilename)
		}
		return nil, errors.New("missing public key for RSA encryption")
	}
	return []byte(cmd.PubKey), nil
}
