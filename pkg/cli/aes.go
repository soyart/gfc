package cli

import (
	"os"
	"strings"

	"github.com/pkg/errors"

	"github.com/artnoi43/gfc/pkg/gfc"
)

type aesCommand struct {
	baseCryptFlags
	AesKeyFilename string `arg:"-k,--key,env:KEY" placeholder:"KEY" help:"256-bit keyfile for AES"`
	AesMode        string `arg:"-m,--mode" default:"GCM" placeholder:"MODE" help:"AES mode"`

	AesKeyFileBytes []byte `arg:"-"`
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
	if cmd.AesKeyFilename == "" {
		return nil, nil
	}
	return os.ReadFile(cmd.AesKeyFilename)
}
