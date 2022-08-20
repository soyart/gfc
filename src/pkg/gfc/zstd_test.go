package gfc

import (
	"bytes"
	"testing"
)

func TestZstdCompDecomp(t *testing.T) {
	b := []byte("this is the input to be compressed")
	in := bytes.NewBuffer(b)

	compressed, err := compressZstd(in)
	if err != nil {
		t.Errorf("error compressing: %s", err.Error())
	}
	decompressed, err := decompressZstd(compressed)
	if err != nil {
		t.Errorf("error decompressing: %s", err.Error())
	}
	if !bytes.Equal(b, decompressed.(*bytes.Buffer).Bytes()) {
		t.Fatalf("unexpected output")
	}
}
