package gfc

import "io"

func Write(w io.Writer, s string) {
	w.Write([]byte(s))
}
