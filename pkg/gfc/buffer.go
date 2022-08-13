package gfc

import "io"

// type Buffer *bytes.Buffer

type Buffer interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	ReadFrom(io.Reader) (int64, error)
	WriteTo(io.Writer) (int64, error)
	Bytes() []byte
}
