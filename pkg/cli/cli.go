package cli

import (
	"bufio"
	"bytes"
	"io"
	"os"

	"github.com/pkg/errors"

	"github.com/artnoi43/gfc/pkg/gfc"
)

// aesCommand and rsaCommand implement this interface
type Command interface {
	infile() (*os.File, error)
	outfile() (*os.File, error)
	decrypt() bool
	isText() bool // Check if gfc gets its input from console prompt
	compression() bool
	algoMode() (gfc.AlgoMode, error)
	encoding() gfc.Encoding
	key() ([]byte, error)
}

func (a *Args) Handle() error {
	var cmd Command
	var algo gfc.Algorithm
	switch {
	case a.AESCommand != nil:
		cmd = a.AESCommand
		algo = gfc.AlgoAES
	case a.RSACommand != nil:
		cmd = a.RSACommand
		algo = gfc.AlgoRSA
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

	buf, err = crypt(buf, key, decrypt, algo, mode)
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
func preProcess(buf gfc.Buffer, decrypt bool, encoding gfc.Encoding, compress bool) (gfc.Buffer, error) {
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

// crypt wraps cryptAES and cryptRSA
func crypt(buf gfc.Buffer, key []byte, decrypt bool, algo gfc.Algorithm, mode gfc.AlgoMode) (gfc.Buffer, error) {
	switch algo {
	case gfc.AlgoAES:
		return cryptAES(buf, key, decrypt, mode)
	case gfc.AlgoRSA:
		return cryptRSA(buf, key, decrypt, mode)
	}
	return nil, errors.New("invalid crypto algorithm")
}

func cryptAES(buf gfc.Buffer, key []byte, decrypt bool, mode gfc.AlgoMode) (gfc.Buffer, error) {
	if decrypt {
		switch mode {
		case gfc.AES_GCM:
			return gfc.DecryptGCM(buf, key)
		case gfc.AES_CTR:
			return gfc.DecryptCTR(buf, key)
		}
	}
	switch mode {
	case gfc.AES_GCM:
		return gfc.EncryptGCM(buf, key)
	case gfc.AES_CTR:
		return gfc.EncryptCTR(buf, key)
	}
	return nil, errors.New("invalid AES mode (should not happen)")
}

func cryptRSA(buf gfc.Buffer, key []byte, decrypt bool, mode gfc.AlgoMode) (gfc.Buffer, error) {
	switch mode {
	case gfc.RSA_OEAP:
		if decrypt {
			return gfc.DecryptRSA(buf, key)
		}
		return gfc.EncryptRSA(buf, key)
	}
	return nil, errors.New("invalid RSA mode (should not happen)")
}

// postProcess modifies the output buffer after encryption/decryption stage before gfc writes it out to outfile
func postProcess(buf gfc.Buffer, decrypt bool, encoding gfc.Encoding, compress bool) (gfc.Buffer, error) {
	if decrypt {
		return gfc.Decompress(compress, buf)
	}
	return gfc.Encode(encoding, buf)
}
