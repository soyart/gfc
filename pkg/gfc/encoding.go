package gfc

// This file provides encoding functionality for gfc
// Current supported encodings are none, base-16 (hexadecimal), and base-64.

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"

	"github.com/pkg/errors"
)

func Decode(encoding Encoding, raw Buffer) (Buffer, error) {
	var decoder io.Reader

	switch encoding {
	case EncodingNone:
		return raw, nil

	case EncodingBase64:
		decoder = base64.NewDecoder(base64.StdEncoding, raw)

	case EncodingHex:
		decoder = hex.NewDecoder(raw)

	default:
		return nil, fmt.Errorf("unknown encoding %d", encoding)
	}

	decoded := new(bytes.Buffer)
	_, err := decoded.ReadFrom(decoder)
	if err != nil {
		return nil, errors.Wrap(err, "io error - cannot read from decoder")
	}

	return decoded, nil
}

func Encode(encoding Encoding, raw Buffer) (Buffer, error) {
	// Need empty interface because base64.NewEncoder returns io.WriteCloser,
	// while hex.NewEncoder returns io.Writer
	var encoder interface{}
	encoded := new(bytes.Buffer)

	switch encoding {
	case EncodingNone:
		return raw, nil

	case EncodingBase64:
		encoder = base64.NewEncoder(base64.StdEncoding, encoded)

		// Base64 encodings operate in 4-byte blocks; when finished writing,
		// the caller must Close the returned encoder to flush any partially written blocks.
		defer func() {
			err := encoder.(io.WriteCloser).Close()
			if err != nil {
				panic("failed to close base64 encoder: " + err.Error())
			}
		}()

	case EncodingHex:
		encoder = hex.NewEncoder(encoded)

	default:
		return nil, errors.New("unknown encoding")
	}

	_, err := raw.WriteTo(encoder.(io.Writer))
	if err != nil {
		return nil, errors.Wrap(err, "io error: can't write to encoder")
	}

	return encoded, nil
}
