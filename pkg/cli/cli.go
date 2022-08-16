package cli

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path"

	"github.com/pkg/errors"

	"github.com/artnoi43/gfc/pkg/gfc"
)

// Gfc represent the actual top-level gfc command.
type Gfc struct {
	AESCommand       *aesCommand      `arg:"subcommand:aes" help:"Use gfc-aes for AES encryption: see 'gfc aes --help'"`
	RSACommand       *rsaCommand      `arg:"subcommand:rsa" help:"Use gfc-rsa for RSA encryption: see 'gfc rsa --help'"`
	XChaCha20Command *chaCha20Command `arg:"subcommand:cc20" help:"Use gfc-cc20 for ChaCha20/XChaCha20-Poly1305 encryption: see 'gfc cc20 --help'"`
}

// All subcommands must implement this interface
type subcommand interface {
	// baseCryptFlags methods have default implementation done by *baseCryptFlags.
	// If an algorithm embeds baseCryptFlags, these methods should already be inherited.
	// You can override these methods with your own algorithm implementation.

	infile() (string, *os.File, error) // infile returns file pointer to the infile
	outfile() string                   // outfile returns outfile filename
	decrypt() bool                     // decrypt returns if user specified decryption operation
	isText() bool                      // isText checks if user wants to manually input text from console prompt
	compression() bool                 // compression checks if user wants to include ZSTD in the pipeline
	algoMode() (gfc.AlgoMode, error)   // algoMode  checks if user specified invalid mode before attempting to read file
	encoding() gfc.Encoding            // encoding returns if user wants to apply encoding to the pipeline, and if so, which one

	// Algorithm methods - not defined in *baseCryptFlags

	key() ([]byte, error) // key returns bytes of user-generated keys for use with crypt
	// crypt performs encryption on buffer 'buf' using key 'key'.
	// Some algorithms may further derive the actual encryption key from 'key'.
	// If 'decrypt' is true, the operation will be decryption
	crypt(mode gfc.AlgoMode, buf gfc.Buffer, key []byte, decrypt bool) (gfc.Buffer, error)
}

// TODO: Extract outfile validation and write into own functions?
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
	isTextInput := cmd.isText()

	// infile is opened early so we know sooner if it's bad.
	// The file pointer is closed by readInfile.
	infileName, infile, err := cmd.infile()
	if err != nil {
		return errors.Wrapf(err, "failed to read infile")
	}
	if infile != os.Stdin {
		infileInfo, err := os.Stat(infileName)
		if err != nil {
			return errors.Wrap(err, "failed to read infile metadata")
		}
		if infileInfo.IsDir() {
			return wrapErrFilename(ErrFileIsDir, infileName)
		}
	}

	// outfile is opened (created) late in this function, just before the final writes
	// so that we don't have hanging file pointer opened for too long before it is written.
	var outfile *os.File
	// True if outfile is (1) not stdout (2) not dir (3) user writable
	var outfileGoodFile bool
	// Validates outfile and returns error before attempting to do anything expensive
	outfileName := cmd.outfile()
	if outfileName != "" {
		if outfileName != "/dev/null" {
			outfileDir := path.Dir(outfileName)
			if err != nil {
				return wrapErrFilename(err, outfileName)
			}
			outfileDirInfo, err := os.Stat(outfileDir)
			if err != nil {
				return wrapErrFilename(ErrBadOutfileDir, outfileName)
			}
			// Check if outfile directory is writable by user
			if !isWritable(outfileDirInfo) {
				// If the directory is unwritable,
				// but there's a file owned and writable by user there.
				outfileInfo, err := os.Stat(outfileName)
				if err != nil {
					// Error reason example: outfile = /some_dir_user_owns/{does not exist}
					return wrapErrFilename(ErrOutfileNotWritable, outfileDir)
				}
				if !isWritable(outfileInfo) {
					// Error reason example: outfile = /etc/fstab
					return wrapErrFilename(ErrOutfileDirNotWritable, outfileName)
				}
			}
		}
		// Normal, writable outfile
		outfileGoodFile = true
	} else {
		// Leave outfileGoodFile false
		outfile = os.Stdout
	}

	decrypt := cmd.decrypt()
	encoding := cmd.encoding()
	compress := cmd.compression()

	buf, err := readInfile(infile, isTextInput)
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

	// Open outfile
	if outfileGoodFile {
		outfile, err = os.OpenFile(outfileName, os.O_RDWR|os.O_CREATE, os.FileMode(0600))
		if err != nil {
			return errors.Wrap(err, "outfile not created")
		}
		closeOutfile := func() {
			if err := outfile.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "failed to close outfile %s: %s\n", outfileName, err.Error())
			}
		}
		// Catch panics and close outfile only if it's not stdout
		defer func() {
			if r := recover(); r != nil {
				fmt.Fprintf(os.Stderr, "panic recovered: %v\n", r)
				closeOutfile()
			}
		}()
		defer closeOutfile()
	}

	// Prepare to close non-stdout outfile when done
	// Write to outfile
	if _, err := buf.WriteTo(outfile); err != nil {
		return errors.Wrapf(err, "failed to write to outfile %s", outfile.Name())
	}

	return nil
}

// readInfile does not use os.ReadFile to read infile, so we must close infile manually.
func readInfile(infile *os.File, isTextInput bool) (gfc.Buffer, error) {
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
