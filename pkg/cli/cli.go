package cli

import (
	"bufio"
	"bytes"
	"io"
	"os"

	"github.com/pkg/errors"

	"github.com/artnoi43/gfc/pkg/gfc"
)

// Args represent the actual top-level gfc command.
type Args struct {
	AESCommand       *aesCommand      `arg:"subcommand:aes" help:"Use gfc-aes for AES encryption"`
	RSACommand       *rsaCommand      `arg:"subcommand:rsa" help:"Use gfc-rsa for RSA encryption"`
	XChaCha20Command *chaCha20Command `arg:"subcommand:cc20" help:"Use gfc-cc20 for ChaCha20/XChaCha20-Poly1305 encryption1"`
}

// aesCommand and rsaCommand implement this interface
type Command interface {
	// baseCryptFlags methods have default implementation done by *baseCryptFlags.
	// If an algorithm embeds *baseCryptFlags, these methods should already be inherited.
	// You can override these methods with your own algorithm implementation.

	infile() (*os.File, error)       // infile returns file pointer to the infile
	outfile() (*os.File, error)      // outfile returns file pointer to the outfile
	decrypt() bool                   // decrypt returns if user specified decryption operation
	isText() bool                    // isText checks if user wants to manually input text from console prompt
	compression() bool               // compression checks if user wants to include ZSTD in the pipeline
	algoMode() (gfc.AlgoMode, error) // algoMode  checks if user specified invalid mode before attempting to read file
	encoding() gfc.Encoding          // encoding returns if user wants to apply encoding to the pipeline, and if so, which one

	// Algorithm methods - not defined in *baseCryptFlags

	key() ([]byte, error) // key returns bytes of user-generated keys for use with crypt
	// crypt performs encryption on buffer 'buf' using key 'key'.
	// Some algorithms may further derive the actual encryption key from 'key'.
	// If 'decrypt' is true, the operation will be decryption
	crypt(mode gfc.AlgoMode, buf gfc.Buffer, key []byte, decrypt bool) (gfc.Buffer, error)
}

func (a *Args) RunCLI() error {
	var cmd Command
	switch {
	case a.AESCommand != nil:
		cmd = a.AESCommand
	case a.RSACommand != nil:
		cmd = a.RSACommand
	case a.XChaCha20Command != nil:
		cmd = a.XChaCha20Command
	default:
		return errors.New("missing subcommand: see gfc --help")
	}

	isTextInput := cmd.isText()
	// infile is closed by readInput
	infile, err := cmd.infile()
	if err != nil {
		return errors.Wrapf(err, "failed to read infile")
	}
	key, err := cmd.key()
	if err != nil {
		return errors.Wrapf(err, "failed to read key")
	}
	// outfile is closed in this function after writing to it by using defer statement.
	outfile, err := cmd.outfile()
	if err != nil {
		return errors.Wrapf(err, "failed to open outfile")
	}
	closeOutfile := func() {
		if outfile != os.Stdout {
			if err := outfile.Close(); err != nil {
				gfc.Write(os.Stderr, "failed to close outfile: "+outfile.Name()+"\n")
			}
		}
	}
	defer func() {
		if r := recover(); r != nil {
			gfc.Write(os.Stderr, "panic recovered\n")
			closeOutfile()
		}
	}()
	defer closeOutfile()

	mode, err := cmd.algoMode()
	if err != nil {
		return errors.Wrap(err, "invalid algorithm mode")
	}
	decrypt := cmd.decrypt()
	encoding := cmd.encoding()
	compress := cmd.compression()

	buf, err := readInput(infile, isTextInput)
	if err != nil {
		return errors.Wrap(err, "failed to read input")
	}

	buf, err = preProcess(buf, decrypt, encoding, compress)
	if err != nil {
		return errors.Wrap(err, "input preprocessing failed")
	}

	buf, err = cmd.crypt(mode, buf, key, decrypt)
	if err != nil {
		return errors.Wrap(err, "cryptography error")
	}

	buf, err = postProcess(buf, decrypt, encoding, compress)
	if err != nil {
		return errors.Wrap(err, "output processing failed")
	}

	if _, err := buf.WriteTo(outfile); err != nil {
		return errors.Wrapf(err, "failed to write to outfile %s", outfile.Name())
	}

	return nil
}

// readInput does not use os.ReadFile to read infile, so we must close infile manually.
func readInput(infile *os.File, isTextInput bool) (gfc.Buffer, error) {
	// Read input from a file or stdin. If from stdin, a "\n" denotes the end of the input.
	var gfcInput gfc.Buffer = new(bytes.Buffer)
	if infile == os.Stdin {
		if isTextInput {
			// Read 1 line from stdin
			scanner := bufio.NewScanner(infile)
			scanner.Scan()
			gfcInput = bytes.NewBuffer(scanner.Bytes())
		} else {
			// TODO: maybe use io.ReadAll?
			// Read whole stdin input
			for {
				stdinBuf := make([]byte, 1024)
				n, err := infile.Read(stdinBuf)
				if n > 0 {
					gfcInput.Write(stdinBuf[:n])
				}
				if err == io.EOF {
					break
				}
				if err != nil {
					return nil, errors.Wrap(err, "failed to read input from stdin")
				}
			}
		}
	} else {
		if _, err := gfcInput.ReadFrom(infile); err != nil {
			return nil, errors.Wrapf(err, "failed to read from infile: %s", infile.Name())
		}
		if err := infile.Close(); err != nil {
			return nil, errors.Wrapf(err, "failed to close infile %s", infile.Name())
		}
	}

	return gfcInput, nil
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
	var err error
	if decrypt {
		// Decryption may need to decide encoded input
		buf, err = gfc.Decode(encoding, buf)
		if err != nil {
			return nil, errors.Wrap(err, "decoding failed")
		}
	} else {
		// Encryption may need to compress input
		buf, err = gfc.Compress(compress, buf)
		if err != nil {
			return nil, errors.Wrap(err, "compression failed")
		}
	}
	return buf, nil
}

// postProcess modifies the output buffer after encryption/decryption stage before gfc writes it out to outfile
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
