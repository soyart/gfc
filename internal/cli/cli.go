package cli

import (
	"github.com/pkg/errors"

	"github.com/soyart/gfc/pkg/gfc"
)

// Gfc represent the actual top-level gfc command.
type Gfc struct {
	CommandAES      *cmdAES      `arg:"subcommand:aes" help:"Use gfc-aes for AES encryption: see 'gfc aes --help'"`
	CommandRSA      *cmdRSA      `arg:"subcommand:rsa" help:"Use gfc-rsa for RSA encryption: see 'gfc rsa --help'"`
	CommandChaCha20 *cmdChaCha20 `arg:"subcommand:cc20" help:"Use gfc-cc20 for ChaCha20/XChaCha20-Poly1305 encryption: see 'gfc cc20 --help'"`
}

type subcommand interface {
	decrypt() bool                   // decrypt returns if user specified decryption operation
	filenameIn() string              // filenameIn returns input filename
	filenameOut() string             // filenameOut returns output filename
	stdinText() bool                 // stdinText returns whether this run takes text input from stdin
	compression() bool               // compression checks if user wants to include ZSTD in the pipeline
	algoMode() (gfc.AlgoMode, error) // algoMode  checks if user specified invalid mode before attempting to read file
	encoding() gfc.Encoding          // encoding returns if user wants to apply encoding to the pipeline, and if so, which one
}

type command interface {
	subcommand

	key() ([]byte, error)
	crypt(mode gfc.AlgoMode, buf gfc.Buffer, key []byte, decrypt bool) (gfc.Buffer, error)
}

// Run is the application code for gfc.
func (g *Gfc) Run() error {
	var cmd command
	switch {
	case g.CommandAES != nil:
		cmd = g.CommandAES

	case g.CommandRSA != nil:
		cmd = g.CommandRSA

	case g.CommandChaCha20 != nil:
		cmd = g.CommandChaCha20

	default:
		return ErrMissingSubcommand
	}

	// Check bad mode before open files
	_, err := cmd.algoMode()
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

	defer infile.Close()

	outfile, err := openOutput(cmd.filenameOut())
	if err != nil {
		return err
	}

	defer outfile.Close()

	buf, err := readInput(infile, cmd.stdinText())
	if err != nil {
		return errors.Wrap(err, "failed to read input")
	}

	buf, err = g.core(cmd, buf, key)
	if err != nil {
		return errors.Wrap(err, "cli.Gfc: core returned error")
	}

	if _, err := buf.WriteTo(outfile); err != nil {
		return errors.Wrapf(err, "failed to write to outfile %s", outfile.Name())
	}

	return nil
}

//nolint:wrapcheck
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

//nolint:wrapcheck
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
	cmd command,
	buf gfc.Buffer,
	key []byte,
) (
	gfc.Buffer,
	error,
) {
	mode, err := cmd.algoMode()
	if err != nil {
		panic("unexpected invalid mode")
	}

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
