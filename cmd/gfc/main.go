package main

import (
	"errors"
	"os"

	"github.com/alexflint/go-arg"

	"github.com/soyart/gfc/internal/cli"
)

const (
	_          = iota // 0
	otherError        // 1
	userError         // 2

	// These strings will be concatenated with error message
	// when writing out to stderr after an error occured in main
	errorMsg     string = "gfc error: "
	userErrorMsg string = "See gfc --help"
)

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

			die(userError, err.Error())

		default:
			die(otherError, err.Error())
		}
	}
}

func die(exitStatus int, msg string) {
	errStr := errorMsg + msg + "\n"

	switch exitStatus {
	case userError:
		errStr = errStr + userErrorMsg + "\n"
	}

	os.Stderr.Write([]byte(errStr))
	os.Exit(exitStatus)
}
