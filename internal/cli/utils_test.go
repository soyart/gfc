package cli

import (
	"os"
	"testing"
)

func TestIsWritable(t *testing.T) {
	tests := map[string]bool{
		"/":    false,
		"/etc": false,
		".":    true,
	}

	for dir, expected := range tests {
		dirInfo, err := os.Stat(dir)
		if err != nil {
			t.Errorf("failed to open %s directory: %s", dir, err.Error())
		}
		if result := isWritable(dirInfo); result != expected {
			t.Fatalf("directory %s - expecting writable %v, got %v (unless this test was run as root)\n", dir, expected, result)
		}
	}
}
