package main

import (
	"fmt"
	"os"

	"github.com/alexflint/go-arg"

	"github.com/artnoi43/gfc/pkg/usecase/cli"
	"github.com/artnoi43/gfc/pkg/usecase/gfc"
)

func main() {
	var args = new(cli.Args)
	arg.MustParse(args)

	if err := args.Handle(); err != nil {
		gfc.Write(os.Stderr, fmt.Sprintf("error: %s\n", err.Error()))
		os.Exit(2)
	}
}
