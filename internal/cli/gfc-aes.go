package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/pkg/errors"

	"github.com/soyart/gfc/pkg/gfc"
)

type aesCommand struct {
	AesMode string `arg:"-m,--mode" default:"GCM" placeholder:"MODE" help:"AES mode"`
	Keyfile string `arg:"-k,--key,env:KEY" placeholder:"KEY" help:"256-bit keyfile for AES"`

	baseCryptFlags
}

func (cmd *aesCommand) algoMode() (gfc.AlgoMode, error) {
	mode := strings.ToUpper(cmd.AesMode)
	switch mode {
	case "GCM":
		return gfc.ModeAesGCM, nil

	case "CTR":
		return gfc.ModeAesCTR, nil
	}

	return gfc.ModeInvalid, errors.Wrapf(ErrInvalidModeAES, "unknown mode %s", cmd.AesMode)
}

func (cmd *aesCommand) key() ([]byte, error) {
	if len(cmd.Keyfile) == 0 {
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
	case gfc.ModeAesGCM:
		if decrypt {
			return gfc.DecryptGCM(buf, key)
		}

		return gfc.EncryptGCM(buf, key)

	case gfc.ModeAesCTR:
		if decrypt {
			return gfc.DecryptCTR(buf, key)
		}

		return gfc.EncryptCTR(buf, key)
	}

	return nil, fmt.Errorf("invalid AES mode %d", mode)
}
