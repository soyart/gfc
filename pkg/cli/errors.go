package cli

import "github.com/pkg/errors"

var (
	// CLI error (user error)

	ErrMissingSubcommand = errors.New("missing subcommand")
	ErrInvalidModeAES    = errors.New("invalid AES mode")

	// I/O error, but also from the user part

	ErrFileIsDir          = errors.New("file is directory")
	ErrBadInfileIsText    = errors.New("cannot read infile and input text simultaneously")
	ErrBadOutfileDir      = errors.New("bad outfile path")
	ErrOutfileNotWritable = errors.New("missing write permission for outfile")
)
