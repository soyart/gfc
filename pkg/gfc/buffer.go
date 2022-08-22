package gfc

import "io"

// type Buffer *bytes.Buffer

type Buffer interface {
	io.Reader
	io.Writer
	io.ReaderFrom
	io.WriterTo
	Len() int
	Bytes() []byte
}
