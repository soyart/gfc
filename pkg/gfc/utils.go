package gfc

// Non-encryption names are defined in this file
// It contains mostly I/O related structs and functions

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
)

var (
	b64Encoding = base64.StdEncoding
)

type File struct {
	fp   *os.File
	Name string
}

func (F *File) Create() *os.File {
	fp, err := os.Create(F.Name)
	if err != nil {
		os.Stderr.Write([]byte("Error creating file: " + F.Name + "\n"))
		os.Exit(1)
	}
	return fp
}

func (F *File) open() error {
	var err error
	if F.fp, err = os.Open(F.Name); err != nil {
		return err
	}
	return nil
}

func (F *File) create() error {
	var err error
	if F.fp, err = os.Create(F.Name); err != nil {
		return err
	}
	return nil
}

func (F *File) ReadFile() (rbuf Buffer) {
	if err := F.open(); err != nil {
		os.Stderr.Write([]byte(
			"Could not open file for reading: " + F.Name + "\n"),
		)
		os.Exit(1)
	}

	defer F.fp.Close()
	rbuf = new(bytes.Buffer)
	rbuf.ReadFrom(F.fp)
	return rbuf
}

func (F *File) WriteFile(obuf Buffer) {
	if err := F.create(); err != nil {
		os.Stderr.Write([]byte(
			"Could not open file for writing: " + F.Name + "\n"),
		)
		os.Exit(1)
	}

	defer F.fp.Close()
	obuf.WriteTo(F.fp)
}

func Decode(encoding Encoding, raw Buffer) (Buffer, error) {
	var decoder io.Reader
	switch encoding {
	case NoEncoding:
		return raw, nil
	case Base64:
		decoder = base64.NewDecoder(b64Encoding, raw)
	case Hex:
		decoder = hex.NewDecoder(raw)
	default:
		return nil, errors.New("unknown encoding")
	}
	decoded := new(bytes.Buffer)
	decoded.ReadFrom(decoder)
	return decoded, nil
}

func Encode(encoding Encoding, raw Buffer) (Buffer, error) {
	// Need empty interface because base64.NewEncoder returns io.WriteCloser,
	// while hex.NewEncoder returns io.Writer
	var encoder interface{}
	encoded := new(bytes.Buffer)
	switch encoding {
	case NoEncoding:
		return raw, nil
	case Base64:
		encoder = base64.NewEncoder(b64Encoding, encoded)
		// Base64 encodings operate in 4-byte blocks; when finished writing,
		// the caller must Close the returned encoder to flush any partially written blocks.
		defer encoder.(io.WriteCloser).Close()
	case Hex:
		encoder = hex.NewEncoder(encoded)
	default:
		return nil, errors.New("unknown encoding")
	}
	raw.WriteTo(encoder.(io.Writer))
	return encoded, nil
}

func Write(w io.Writer, s string) {
	w.Write([]byte(s))
}