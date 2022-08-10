package gfc

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
		return nil, errors.Wrap(err, "new zstd encoder failed")
	}
	raw.WriteTo(compressor)
	compressor.Close()
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
	decompressed.ReadFrom(decompressor)
	decompressor.Close()
	return decompressed, nil
}
