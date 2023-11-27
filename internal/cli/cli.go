package cli

import (
	"github.com/pkg/errors"

	"github.com/soyart/gfc/pkg/gfc"
)

// Gfc represent the actual top-level gfc command.
type Gfc struct {
	AESCommand       *aesCommand      `arg:"subcommand:aes" help:"Use gfc-aes for AES encryption: see 'gfc aes --help'"`
	RSACommand       *rsaCommand      `arg:"subcommand:rsa" help:"Use gfc-rsa for RSA encryption: see 'gfc rsa --help'"`
	XChaCha20Command *chaCha20Command `arg:"subcommand:cc20" help:"Use gfc-cc20 for ChaCha20/XChaCha20-Poly1305 encryption: see 'gfc cc20 --help'"`
}

type standardCommand interface {
	decrypt() bool                   // decrypt returns if user specified decryption operation
	filenameIn() string              // filenameIn returns input filename
	filenameOut() string             // filenameOut returns output filename
	stdinText() bool                 // stdinText returns whether this run takes text input from stdin
	compression() bool               // compression checks if user wants to include ZSTD in the pipeline
	algoMode() (gfc.AlgoMode, error) // algoMode  checks if user specified invalid mode before attempting to read file
	encoding() gfc.Encoding          // encoding returns if user wants to apply encoding to the pipeline, and if so, which one
}

type subcommand interface {
	standardCommand

	key() ([]byte, error)
	crypt(mode gfc.AlgoMode, buf gfc.Buffer, key []byte, decrypt bool) (gfc.Buffer, error)
}

// TODO: Extract outfile validation and write into own functions?
// Run is the application code for gfc.
func (g *Gfc) Run() error {
	var cmd subcommand
	switch {
	case g.AESCommand != nil:
		cmd = g.AESCommand

	case g.RSACommand != nil:
		cmd = g.RSACommand

	case g.XChaCha20Command != nil:
		cmd = g.XChaCha20Command

	default:
		return ErrMissingSubcommand
	}

	mode, err := cmd.algoMode()
	if err != nil {
		return errors.Wrap(err, "invalid algorithm mode")
	}

	key, err := cmd.key()
	if err != nil {
		return errors.Wrapf(err, "failed to read key")
	}

	infile, err := openInput(cmd.filenameIn(), cmd.stdinText())
	if err != nil {
		return err
	}

	outfile, err := openOutput(cmd.filenameOut())
	if err != nil {
		return err
	}

	buf, err := readInput(infile, cmd.stdinText())
	if err != nil {
		return errors.Wrap(err, "failed to read input")
	}

	buf, err = g.core(cmd, mode, buf, key)
	if err != nil {
		return errors.Wrap(err, "cli.Gfc: core returned error")
	}

	if _, err := buf.WriteTo(outfile); err != nil {
		return errors.Wrapf(err, "failed to write to outfile %s", outfile.Name())
	}

	return nil
}

// preProcess creates and modifies the input buffer before encryption/decryption stage.
func preProcess(
	buf gfc.Buffer,
	decrypt bool,
	encoding gfc.Encoding,
	compress bool,
) (
	gfc.Buffer,
	error,
) {
	if decrypt {
		return gfc.Decode(encoding, buf)
	}

	return gfc.Compress(compress, buf)
}

// postProcess modifies the output buffer after encryption/decryption stage, jusr before gfc writes the buffer out to outfile
func postProcess(
	buf gfc.Buffer,
	decrypt bool,
	encoding gfc.Encoding,
	compress bool,
) (
	gfc.Buffer,
	error,
) {
	if decrypt {
		return gfc.Decompress(compress, buf)
	}

	return gfc.Encode(encoding, buf)
}

// core pre-processes, encrypts/decrypts, and post-processes buf.
func (g *Gfc) core(
	cmd subcommand,
	mode gfc.AlgoMode,
	buf gfc.Buffer,
	key []byte,
) (
	gfc.Buffer,
	error,
) {
	var err error
	decrypt := cmd.decrypt()
	encoding := cmd.encoding()
	compress := cmd.compression()

	buf, err = preProcess(buf, decrypt, encoding, compress)
	if err != nil {
		return nil, errors.Wrap(err, "input preprocessing failed")
	}

	buf, err = cmd.crypt(mode, buf, key, decrypt)
	if err != nil {
		return nil, errors.Wrap(err, "cryptography error")
	}

	buf, err = postProcess(buf, decrypt, encoding, compress)
	if err != nil {
		return nil, errors.Wrap(err, "output processing failed")
	}

	return buf, nil
}
