package cli

import (
	"os"
	"strings"

	"github.com/pkg/errors"

	"github.com/artnoi43/gfc/pkg/gfc"
)

// Hard-coded flag values for baseCryptFlags.EncodingFlag, used in baseCryptFlags.encoding()
const (
	b64lagValue     = "B64"
	base64FlagValue = "BASE64"
	hexFlagValue    = "HEX"
	hFlagValue      = "H"
)

// baseCryptFlags represents the shared gfc CLI flags between subcommands.
// If you are adding a new algorithm, you don't have to use baseCryptFlags,
// just implement Command interface with any means.
type baseCryptFlags struct {
	StdinText    bool   `arg:"-t,--text" default:"false" help:"Enter a text line manually to stdin"`
	DecryptFlag  bool   `arg:"-d,--decrypt" default:"false" help:"Decrypt mode"`
	InfileFlag   string `arg:"-i,--infile" placeholder:"IN" help:"Input filename, stdin will be used if omitted"`
	OutfileFlag  string `arg:"-o,--outfile" placeholder:"OUT" help:"Output filename, stdout will be used if omitted"`
	EncodingFlag string `arg:"-e,--encoding" placeholder:"ENC" help:"'base64' or 'hex' encoding for input or output"`
	CompressFlag bool   `arg:"-c,--compress" default:"false" help:"Use ZSTD compression"`
}

// openInfileOrOrStdin returns fd to file 'fname',
// or it returns os.Stdin if fname is empty
func openInfileOrOrStdin(fname string, isText bool) (*os.File, error) {
	if fname == "" {
		if isText {
			os.Stdout.WriteString("Text input:\n")
		}
		return os.Stdin, nil
	}
	if isText {
		return nil, errors.Wrapf(ErrBadInfileIsText, "got both infile %s and --text flag", fname)
	}
	return os.Open(fname)
}

// Caller must call *os.File.Close() on their own
func (f *baseCryptFlags) infile() (string, *os.File, error) {
	fp, err := openInfileOrOrStdin(f.InfileFlag, f.isText())
	if err != nil {
		return "$BADINFILE", nil, err
	}
	return f.InfileFlag, fp, nil
}

// Any struct that embeds *baseCryptFlags will inherit this
func (f *baseCryptFlags) isText() bool {
	return f.StdinText
}

// Caller must call *os.File.Close() on their own
func (f *baseCryptFlags) outfile() string {
	return f.OutfileFlag
}

func (f *baseCryptFlags) decrypt() bool {
	return f.DecryptFlag
}

func (f *baseCryptFlags) compression() bool {
	return f.CompressFlag
}

func (f *baseCryptFlags) encoding() gfc.Encoding {
	// Check with all uppercase enums
	encoding := strings.ToUpper(f.EncodingFlag)
	if encoding == b64lagValue || encoding == base64FlagValue {
		return gfc.EncodingBase64
	} else if encoding == hFlagValue || encoding == hexFlagValue {
		return gfc.EncodingHex
	}

	return gfc.EncodingNone
}
