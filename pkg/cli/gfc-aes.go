package cli

import (
	"os"
	"strings"

	"github.com/pkg/errors"

	"github.com/artnoi43/gfc/pkg/gfc"
)

type aesCommand struct {
	baseCryptFlags
	AesMode string `arg:"-m,--mode" default:"GCM" placeholder:"MODE" help:"AES mode"`
	Keyfile string `arg:"-k,--key,env:KEY" placeholder:"KEY" help:"256-bit keyfile for AES"`
}

func (cmd *aesCommand) algoMode() (gfc.AlgoMode, error) {
	mode := cmd.AesMode
	switch {
	case strings.EqualFold(mode, "GCM"):
		return gfc.AES_GCM, nil
	case strings.EqualFold(mode, "CTR"):
		return gfc.AES_CTR, nil
	}
	return gfc.InvalidAlgoMode, errors.New("unknown AES mode: " + mode)
}

func (cmd *aesCommand) key() ([]byte, error) {
	if cmd.Keyfile == "" {
		return nil, nil
	}
	return os.ReadFile(cmd.Keyfile)
}

func (cmd *aesCommand) crypt(
	mode gfc.AlgoMode,
	buf gfc.Buffer,
	key []byte,
	decrypt bool,
) (
	gfc.Buffer,
	error,
) {
	switch mode {
	case gfc.AES_GCM:
		if decrypt {
			return gfc.DecryptGCM(buf, key)
		}
		return gfc.EncryptGCM(buf, key)
	case gfc.AES_CTR:
		if decrypt {
			return gfc.DecryptCTR(buf, key)
		}
		return gfc.EncryptCTR(buf, key)
	}
	return nil, errors.New("invalid AES mode (should not happen)")
}
