package cli

import (
	"bufio"
	"bytes"
	"os"

	"github.com/pkg/errors"

	"github.com/soyart/gfc/pkg/gfc"
)

func openInput(filenameIn string, stdinText bool) (*os.File, error) {
	if stdinText || len(filenameIn) == 0 {
		return os.Stdin, nil
	}

	infileInfo, err := os.Stat(filenameIn)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read infile metadata")
	}

	if infileInfo.IsDir() {
		return nil, wrapErrFilename(ErrFileIsDir, filenameIn)
	}

	infile, err := os.Open(filenameIn)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open file %s", filenameIn)
	}

	return infile, nil
}

func openOutput(filenameOut string) (*os.File, error) {
	if len(filenameOut) == 0 {
		return os.Stdout, nil
	}

	outfile, err := os.OpenFile(filenameOut, os.O_RDWR|os.O_CREATE, os.FileMode(0o600))
	if err != nil {
		return nil, errors.Wrapf(err, "failed to open outfile %s", filenameOut)
	}

	return outfile, nil
}

func readInput(infile *os.File, stdinText bool) (gfc.Buffer, error) {
	if stdinText {
		// Read 1 line from stdin
		scanner := bufio.NewScanner(infile)
		scanner.Scan()

		return bytes.NewBuffer(scanner.Bytes()), nil
	}

	input := new(bytes.Buffer)

	_, err := input.ReadFrom(infile)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to read from infile %s", infile.Name())
	}

	return input, nil
}
