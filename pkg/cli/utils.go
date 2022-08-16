package cli

import (
	"os"

	"github.com/pkg/errors"
)

// TODO: Verify that this works on Windows too,
// otherwise we'll need to create Windows-specific
// like this https://stackoverflow.com/questions/20026320/how-to-tell-if-folder-exists-and-is-writable
func isWritable(info os.FileInfo) bool {
	if info.Mode().Perm()&(1<<(uint(7))) == 0 {
		return false
	}
	return true
}

func wrapErrFilename(err error, fname string) error {
	return errors.Wrapf(err, "bad file '%s'", fname)
}
