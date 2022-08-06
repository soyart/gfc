package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/artnoi43/gfc/pkg/usecase/gfc"
)

type aesCommand struct {
	baseCryptFlags
	AesKeyFilename string `arg:"-k,--key,env:KEY" placeholder:"KEY" help:"256-bit keyfile for AES"`
	AesMode        string `arg:"-m,--mode" default:"GCM" placeholder:"MODE" help:"AES mode"`

	AesKeyFileBytes []byte `arg:"-"`
}

// Caller must call *os.File.Close() on their own
func (cmd *aesCommand) Infile() (*os.File, error) {
	return cmd.baseCryptFlags.infile()
}

// Caller must call *os.File.Close() on their own
func (cmd *aesCommand) Outfile() (*os.File, error) {
	return cmd.baseCryptFlags.outfile()
}

func (cmd *aesCommand) Decrypt() bool {
	return cmd.baseCryptFlags.decrypt()
}

func (cmd *aesCommand) AlgoMode() (gfc.AlgoMode, error) {
	mode := cmd.AesMode
	switch {
	case strings.EqualFold(mode, "GCM"):
		return gfc.AES_GCM, nil
	case strings.EqualFold(mode, "CTR"):
		return gfc.AES_CTR, nil
	}
	return gfc.InvalidAlgoMode, fmt.Errorf("unknown AES mode: %s", mode)
}

func (cmd *aesCommand) Encoding() gfc.Encoding {
	return cmd.baseCryptFlags.encoding()
}

func (cmd *aesCommand) Key() ([]byte, error) {
	if cmd.AesKeyFilename == "" {
		return nil, nil
	}
	return os.ReadFile(cmd.AesKeyFilename)
}
