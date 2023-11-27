package cli

import (
	"strings"

	"github.com/soyart/gfc/pkg/gfc"
)

// Hard-coded flag values for baseCryptFlags.EncodingFlag, used in baseCryptFlags.encoding()
const (
	b64lagValue     = "B64"
	base64FlagValue = "BASE64"
	hexFlagValue    = "HEX"
	hFlagValue      = "H"
)

// baseCommand represents the shared gfc CLI flags between subcommands.
// If you are adding a new algorithm, you don't have to use baseCommand,
// just implement Command interface with any means.
type baseCommand struct {
	StdinText    bool   `arg:"-t,--text" default:"false" help:"Enter a text line manually to stdin"`
	DecryptFlag  bool   `arg:"-d,--decrypt" default:"false" help:"Decrypt mode"`
	InfileFlag   string `arg:"-i,--infile" placeholder:"IN" help:"Input filename, stdin will be used if omitted"`
	OutfileFlag  string `arg:"-o,--outfile" placeholder:"OUT" help:"Output filename, stdout will be used if omitted"`
	EncodingFlag string `arg:"-e,--encoding" placeholder:"ENC" help:"'base64' or 'hex' encoding for input or output"`
	CompressFlag bool   `arg:"-c,--compress" default:"false" help:"Use ZSTD compression"`
}

func (f *baseCommand) filenameIn() string {
	return f.InfileFlag
}

func (f *baseCommand) filenameOut() string {
	return f.OutfileFlag
}

// Any struct that embeds *baseCryptFlags will inherit this
func (f *baseCommand) stdinText() bool {
	return f.StdinText
}

// Caller must call *os.File.Close() on their own
func (f *baseCommand) outfile() string {
	return f.OutfileFlag
}

func (f *baseCommand) decrypt() bool {
	return f.DecryptFlag
}

func (f *baseCommand) compression() bool {
	return f.CompressFlag
}

func (f *baseCommand) encoding() gfc.Encoding {
	switch strings.ToUpper(f.EncodingFlag) {
	case b64lagValue, base64FlagValue:
		return gfc.EncodingBase64

	case hFlagValue, hexFlagValue:
		return gfc.EncodingHex
	}

	return gfc.EncodingNone
}
