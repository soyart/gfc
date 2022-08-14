package main

import (
	"errors"
	"os"

	"github.com/alexflint/go-arg"

	"github.com/artnoi43/gfc/pkg/cli"
	"github.com/artnoi43/gfc/pkg/gfc"
)

func main() {
	var args = new(cli.Args)
	arg.MustParse(args)

	if err := args.RunCLI(); err != nil {
		if errors.Is(err, cli.ErrMissingSubcommand) {
			gfc.Write(os.Stderr, err.Error()+": see gfc --help\n")
			os.Exit(1)
		}
		gfc.Write(os.Stderr, "error: "+err.Error()+"\n")
		os.Exit(2)
	}
}
