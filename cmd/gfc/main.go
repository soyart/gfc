package main

import (
	"os"

	"github.com/alexflint/go-arg"
	"github.com/pkg/errors"

	"github.com/soyart/gfc/internal/cli"
)

const (
	errOtherError = iota + 1
	errUserError

	msgErr  string = "gfc error: "
	msgHelp string = "See gfc --help"
)

//nolint:wrapcheck
func die(exitStatus int, msg string) {
	errStr := msgErr + msg + "\n"

	if exitStatus == errUserError {
		errStr = errStr + msgHelp + "\n"
	}

	os.Stderr.Write([]byte(errStr))
	os.Exit(exitStatus)
}

func main() {
	gfcCli := new(cli.Gfc)
	arg.MustParse(gfcCli)

	if err := gfcCli.Run(); err != nil {
		switch {
		case
			errors.Is(err, cli.ErrMissingSubcommand),
			errors.Is(err, cli.ErrFileIsDir),
			errors.Is(err, cli.ErrOutfileNotWritable),
			errors.Is(err, cli.ErrBadInfileIsText),
			errors.Is(err, cli.ErrBadOutfileDir),
			errors.Is(err, cli.ErrInvalidModeAES):

			die(errUserError, err.Error())

		default:
			die(errOtherError, err.Error())
		}
	}
}
