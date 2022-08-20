package cli

import (
	"os"

	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// TODO: UNIX only - Windows not supported
func isWritable(info os.FileInfo) bool {
	return unix.Access(info.Name(), unix.W_OK) == nil
}

func wrapErrFilename(err error, fname string) error {
	return errors.Wrapf(err, "bad file '%s'", fname)
}
