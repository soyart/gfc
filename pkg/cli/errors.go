package cli

type cliError uint8

const (
	ErrMissingSubcommand cliError = iota
	ErrInvalidModeAES
	ErrFileIsDir
	ErrBadInfileIsText
	ErrBadOutfileDir
	ErrOutfileDirNotWritable
	ErrOutfileNotWritable
)

func (err cliError) Error() string {
	switch err {
	case ErrMissingSubcommand:
		return "missing subcommand"
	case ErrInvalidModeAES:
		return "invalid AES mode"
	case ErrFileIsDir:
		return "file is directory"
	case ErrBadInfileIsText:
		return "cannot read infile and input text simultaneously"
	case ErrBadOutfileDir:
		return "bad outfile path"
	case ErrOutfileDirNotWritable:
		return "missing write permission in outfile directory"
	case ErrOutfileNotWritable:
		return "missing write permission for outfile"
	}
	return "unknown CLI error (should not happen)"
}
