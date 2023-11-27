package cli

import (
	"fmt"
	"os"
	"strings"

	"github.com/soyart/gfc/pkg/gfc"
)

type chaCha20Command struct {
	ChaCha20Mode string `arg:"-m, --mode" placeholder:"[cc20 | xcc20]" default:"xcc20" help:"Supply any string containing 'x' for XChaCha20-Poly1305, and any string without 'x' for ChaCha20-Poly1305"`
	Keyfile      string `arg:"-k,--key,env:KEY" placeholder:"KEY" help:"256-bit Keyfile for AES"`

	baseCryptFlags
}

// Only XChaCha20-Poly1305 is supported for family of ChaCha20 ciphers
func (cmd *chaCha20Command) algoMode() (gfc.AlgoMode, error) {
	if strings.Contains(cmd.ChaCha20Mode, "x") || strings.Contains(cmd.ChaCha20Mode, "X") {
		return gfc.ModeXChaCha20Poly1305, nil
	}

	return gfc.ModeChaCha20Poly1305, nil
}

func (cmd *chaCha20Command) key() ([]byte, error) {
	if len(cmd.Keyfile) == 0 {
		return nil, nil
	}

	return os.ReadFile(cmd.Keyfile)
}

func (cmd *chaCha20Command) crypt(
	mode gfc.AlgoMode,
	buf gfc.Buffer,
	key []byte,
	decrypt bool,
) (
	gfc.Buffer,
	error,
) {
	switch mode {
	case gfc.ModeXChaCha20Poly1305:
		if decrypt {
			return gfc.DecryptXChaCha20Poly1305(buf, key)
		}

		return gfc.EncryptXChaCha20Poly1305(buf, key)

	case gfc.ModeChaCha20Poly1305:
		if decrypt {
			return gfc.DecryptChaCha20Poly1305(buf, key)
		}

		return gfc.EncryptChaCha20Poly1305(buf, key)
	}

	return nil, fmt.Errorf("invalid ChaCha20 mode %d (should not happen)", mode)
}
