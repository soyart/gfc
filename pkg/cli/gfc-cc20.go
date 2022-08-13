package cli

import (
	"os"

	"github.com/artnoi43/gfc/pkg/gfc"
)

type ChaCha20Command struct {
	baseCryptFlags
	Keyfile string `arg:"-k,--key,env:KEY" placeholder:"KEY" help:"256-bit Keyfile for AES"`
}

// Only XChaCha20-Poly1305 is supported for family of ChaCha20 ciphers
func (cmd *ChaCha20Command) algoMode() (gfc.AlgoMode, error) {
	return gfc.XChaCha20_Poly1305, nil
}

func (cmd *ChaCha20Command) key() ([]byte, error) {
	if cmd.Keyfile == "" {
		return nil, nil
	}
	return os.ReadFile(cmd.Keyfile)
}
