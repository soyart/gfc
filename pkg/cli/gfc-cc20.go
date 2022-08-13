package cli

import (
	"os"
	"strings"

	"github.com/artnoi43/gfc/pkg/gfc"
)

type ChaCha20Command struct {
	baseCryptFlags
	Keyfile      string `arg:"-k,--key,env:KEY" placeholder:"KEY" help:"256-bit Keyfile for AES"`
	ChaCha20Mode string `arg:"-m, --mode" placeholder:"[cc20 | xcc20]" default:"xcc20" help:"Supply any string containing 'x' for XChaCha20-Poly1305, and any string without 'x' for ChaCha20-Poly1305"`
}

// Only XChaCha20-Poly1305 is supported for family of ChaCha20 ciphers
func (cmd *ChaCha20Command) algoMode() (gfc.AlgoMode, error) {
	if strings.Contains(cmd.ChaCha20Mode, "x") || strings.Contains(cmd.ChaCha20Mode, "X") {
		return gfc.XChaCha20_Poly1305, nil
	}
	return gfc.ChaCha20_Poly1305, nil
}

func (cmd *ChaCha20Command) key() ([]byte, error) {
	if cmd.Keyfile == "" {
		return nil, nil
	}
	return os.ReadFile(cmd.Keyfile)
}
