package cli

import (
	"os"

	"github.com/pkg/errors"

	"github.com/artnoi43/gfc/pkg/usecase/gfc"
)

type rsaCommand struct {
	baseCryptFlags
	PubKey string `arg:"-p,--public-key,env:PUB" placeholder:"PUB" help:"Public key string - e.g.: 'gfc rsa --public-key=$(< id_rsa.pub) ...'"`
	PriKey string `arg:"-P,--private-key,env:PRI" placeholder:"PRI" help:"Private key string - e.g.: 'gfc rsa --private-key=$(< id_rsa) ...'"`
}

// Caller must call *os.File.Close() on their own
func (cmd *rsaCommand) Infile() (*os.File, error) {
	return cmd.baseCryptFlags.infile()
}

// Caller must call *os.File.Close() on their own
func (cmd *rsaCommand) Outfile() (*os.File, error) {
	return cmd.baseCryptFlags.outfile()
}

func (cmd *rsaCommand) Decrypt() bool {
	return cmd.baseCryptFlags.decrypt()
}

// rsaCommand only supports 1 RSA mode for now (OEAP)
func (cmd *rsaCommand) AlgoMode() (gfc.AlgoMode, error) {
	return gfc.RSA_OEAP, nil
}

func (cmd *rsaCommand) Encoding() gfc.Encoding {
	return cmd.baseCryptFlags.encoding()
}

// Unlike with AES, gfc will not be reading either of the keypair from files.
// Instead, users will provide the keys as string
func (cmd *rsaCommand) Key() ([]byte, error) {
	if cmd.DecryptFlag {
		if cmd.PriKey == "" {
			return nil, errors.New("missing private key for RSA decryption")
		}
		return []byte(cmd.PriKey), nil
	}
	// RSA Encryption
	if cmd.PubKey == "" {
		return nil, errors.New("missing public key for RSA encryption")
	}
	return []byte(cmd.PubKey), nil
}
