package main

import (
	"errors"
	"os"

	"github.com/alexflint/go-arg"

	"github.com/artnoi43/gfc/internal/cli"
)

const (
	// Exit statuses for different errors
	otherError int = 1
	userError  int = 2

	// These strings will be concatenated with error message
	// when writing out to stderr after an error occured in main
	errorMsg     string = "gfc error: "
	userErrorMsg string = "See gfc --help"
)

func main() {
	var gfcCli = new(cli.Gfc)
	arg.MustParse(gfcCli)

	if err := gfcCli.Run(); err != nil {
		// The cases inside the switch block is user error,
		// and gfc will exit with status 1
		switch {
		case errors.Is(err, cli.ErrMissingSubcommand):
			fallthrough
		case errors.Is(err, cli.ErrFileIsDir):
			fallthrough
		case errors.Is(err, cli.ErrOutfileNotWritable):
			fallthrough
		case errors.Is(err, cli.ErrBadInfileIsText):
			fallthrough
		case errors.Is(err, cli.ErrBadOutfileDir):
			fallthrough
		case errors.Is(err, cli.ErrInvalidModeAES):
			die(userError, err.Error())
		}

		// Non-user error
		die(otherError, err.Error())
	}
}

func die(exitStatus int, msg string) {
	// Concat strings, bc why not?
	errStr := errorMsg + msg + "\n"

	switch exitStatus {
	case userError:
		errStr = errStr + userErrorMsg + "\n"
	}

	os.Stderr.Write([]byte(errStr))
	os.Exit(exitStatus)
}
