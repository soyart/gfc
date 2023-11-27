package gfc

// This file provides compression functionality for gfc.
// Z-standard is the only supported algorithm.

import (
	"bytes"

	"github.com/klauspost/compress/zstd"
	"github.com/pkg/errors"
)

func Compress(compressOption bool, raw Buffer) (Buffer, error) {
	if compressOption {
		return compressZstd(raw)
	}

	return raw, nil
}

func compressZstd(raw Buffer) (Buffer, error) {
	var compressed Buffer = new(bytes.Buffer)
	compressor, err := zstd.NewWriter(compressed)
	if err != nil {
		return nil, errors.Wrap(err, "new zstd compressor failed")
	}

	_, err = raw.WriteTo(compressor)
	if err != nil {
		return nil, errors.Wrap(err, "failed to compress with zstd")
	}

	defer func() {
		if err = compressor.Close(); err != nil {
			panic("failed to close zstd compressor: " + err.Error())
		}
	}()

	return compressed, nil
}

func Decompress(decompressOption bool, raw Buffer) (Buffer, error) {
	if decompressOption {
		return decompressZstd(raw)
	}

	return raw, nil
}

func decompressZstd(compressed Buffer) (Buffer, error) {
	var decompressed Buffer = new(bytes.Buffer)
	decompressor, err := zstd.NewReader(compressed)
	if err != nil {
		return nil, errors.Wrap(err, "new zstd decoder failed")
	}

	defer decompressor.Close()

	_, err = decompressed.ReadFrom(decompressor)
	if err != nil {
		return nil, errors.Wrap(err, "failed to decompress with zstd")
	}

	return decompressed, nil
}
