package cli

import (
	"fmt"
	"os"

	"github.com/pkg/errors"

	"github.com/soyart/gfc/pkg/gfc"
)

type rsaCommand struct {
	PubKey         string `arg:"env:PUB" placeholder:"PUB" help:"Public key string - e.g.: 'PUB=$(< id_rsa.pub) gfc rsa ...'"`
	PriKey         string `arg:"env:PRI" placeholder:"PRI" help:"Private key string - e.g.: 'PRI=$(< id_rsa) gfc rsa -d ...'"`
	PubkeyFilename string `arg:"-p,--public-key" placeholder:"PUBFILE" help:"Public key filename"`
	PriKeyFilename string `arg:"-P,--private-key" placeholder:"PRIFILE" help:"Private key filename"`

	baseCommand
}

// rsaCommand only supports 1 RSA mode for now (OEAP)
func (cmd *rsaCommand) algoMode() (gfc.AlgoMode, error) {
	return gfc.ModeRsaOEAP, nil
}

// rsaCommand will give key strings priority over key filenames
func (cmd *rsaCommand) key() ([]byte, error) {
	var key, keyFilename string

	if cmd.DecryptFlag {
		key = cmd.PriKey
		keyFilename = cmd.PriKeyFilename

	} else {
		key = cmd.PubKey
		keyFilename = cmd.PubkeyFilename
	}

	if len(key) > 0 {
		return []byte(key), nil
	}

	if len(keyFilename) > 0 {
		return os.ReadFile(keyFilename)
	}

	return nil, errors.New("empty rsa key and key filename")
}

func (cmd *rsaCommand) crypt(
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
