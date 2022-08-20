package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/alexflint/go-arg"

	"github.com/artnoi43/gfc/pkg/cli"
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
			fmt.Fprintf(os.Stderr, "error: %s\nSee gfc --help\n", err.Error())
			os.Exit(1)
		}

		// Non-user error
		fmt.Fprintf(os.Stderr, "error: %s\n", err.Error())
		os.Exit(2)
	}
}
