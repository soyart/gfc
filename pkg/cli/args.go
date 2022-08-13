package cli

import (
	"os"
	"strings"

	"github.com/artnoi43/gfc/pkg/gfc"
)

// baseCryptFlags represents the shared gfc CLI flags between AES and RSA subcommands.
type baseCryptFlags struct {
	DecryptFlag  bool   `arg:"-d,--decrypt" default:"false" help:"Decrypt mode"`
	StdinText    bool   `arg:"-t,--text" default:"false" help:"Enter a text line manually to stdin"`
	CompressFlag bool   `arg:"-c,--compress" default:"false" help:"Use ZSTD compression"`
	InfileFlag   string `arg:"-i,--infile" placeholder:"IN" help:"Input filename, stdin will be used if omitted"`
	EncodingFlag string `arg:"-e,--encoding" placeholder:"ENC" help:"'base64' or 'hex' encoding for input or output"`
	OutfileFlag  string `arg:"-o,--outfile" placeholder:"OUT" help:"Output filename, stdout will be used if omitted"`
}

type Args struct {
	AESCommand       *aesCommand      `arg:"subcommand:aes" help:"Use gfc-aes for AES encryption"`
	RSACommand       *rsaCommand      `arg:"subcommand:rsa" help:"Use gfc-rsa for RSA encryption"`
	XChaCha20Command *ChaCha20Command `arg:"subcommand:cc20" help:"Use gfc-cc20 for ChaCha20/XChaCha20-Poly1305 encryption1"`
}

func infile(fname string, isText bool) (*os.File, error) {
	if fname == "" {
		if isText {
			gfc.Write(os.Stdout, "Text input:\n")
		}
		return os.Stdin, nil
	}
	return os.Open(fname)
}

func outfile(fname string) (*os.File, error) {
	if fname == "" {
		return os.Stdout, nil
	}

	return os.Create(fname)
}

// Caller must call *os.File.Close() on their own
func (f *baseCryptFlags) infile() (*os.File, error) {
	return infile(f.InfileFlag, f.isText())
}

// Any struct that embeds *baseCryptFlags will inherit this
func (f *baseCryptFlags) isText() bool {
	return f.StdinText
}

// Caller must call *os.File.Close() on their own
func (f *baseCryptFlags) outfile() (*os.File, error) {
	return outfile(f.OutfileFlag)
}

func (f *baseCryptFlags) decrypt() bool {
	return f.DecryptFlag
}

func (f *baseCryptFlags) compression() bool {
	return f.CompressFlag
}

func (f *baseCryptFlags) encoding() gfc.Encoding {
	encoding := f.EncodingFlag
	if strings.EqualFold(encoding, "B64") || strings.EqualFold(encoding, "BASE64") {
		return gfc.Base64
	} else if strings.EqualFold(encoding, "H") || strings.EqualFold(encoding, "HEX") {
		return gfc.Hex
	}
	return gfc.NoEncoding
}
