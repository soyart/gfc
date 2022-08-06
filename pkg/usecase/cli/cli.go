package cli

import (
	"bufio"
	"bytes"
	"os"
	"strings"

	"github.com/pkg/errors"

	"github.com/artnoi43/gfc/pkg/usecase/gfc"
)

// aesCommand and rsaCommand implement this interface
type Command interface {
	Infile() (*os.File, error)
	Outfile() (*os.File, error)
	Decrypt() bool
	AlgoMode() (gfc.AlgoMode, error)
	Encoding() gfc.Encoding
	Key() ([]byte, error)
}

func infile(fname string) (*os.File, error) {
	if fname == "" {
		gfc.Write(os.Stdout, "Text input:\n")
		return os.Stdin, nil
	}
	return os.Open(fname)
}

func outfile(fname string) (*os.File, error) {
	if fname == "" {
		return os.Stdout, nil
	}

	return os.Create(fname)
}

// Caller must call *os.File.Close() on their own
func (f *baseCryptFlags) infile() (*os.File, error) {
	return infile(f.InfileFlag)
}

// Caller must call *os.File.Close() on their own
func (f *baseCryptFlags) outfile() (*os.File, error) {
	return outfile(f.OutfileFlag)
}

func (f *baseCryptFlags) decrypt() bool {
	return f.DecryptFlag
}

func (f *baseCryptFlags) encoding() gfc.Encoding {
	encoding := f.EncodingFlag
	if strings.EqualFold(encoding, "B64") || strings.EqualFold(encoding, "BASE64") {
		return gfc.Base64
	} else if strings.EqualFold(encoding, "H") || strings.EqualFold(encoding, "HEX") {
		return gfc.Hex
	}
	return gfc.NoEncoding
}

func (a *Args) Handle() error {
	var cmd Command
	// g := &goFileCrypt{}
	var algo gfc.Algorithm
	switch {
	case a.AESCommand != nil:
		cmd = a.AESCommand
		algo = gfc.AlgoAES
	case a.RSACommand != nil:
		cmd = a.RSACommand
		algo = gfc.AlgoRSA
	}

	infile, err := cmd.Infile()
	if err != nil {
		return errors.Wrapf(err, "failed to read infile")
	}
	key, err := cmd.Key()
	if err != nil {
		return errors.Wrapf(err, "failed to read key")
	}
	outfile, err := cmd.Outfile()
	if err != nil {
		return errors.Wrapf(err, "failed to open outfile")
	}
	mode, err := cmd.AlgoMode()
	if err != nil {
		return errors.Wrap(err, "invalid algorithm mode")
	}
	decrypt := cmd.Decrypt()
	encoding := cmd.Encoding()

	buf, err := preprocess(infile, decrypt, encoding)
	if err != nil {
		return errors.Wrap(err, "input preprocessing failed")
	}

	buf, err = crypt(buf, key, decrypt, algo, mode)
	if err != nil {
		return errors.Wrap(err, "cryptography error")
	}

	buf, err = postprocess(buf, decrypt, encoding)
	if err != nil {
		return errors.Wrap(err, "output processing failed")
	}

	if _, err := buf.WriteTo(outfile); err != nil {
		return errors.Wrapf(err, "failed to write to outfile %s", outfile.Name())
	}

	return outfile.Close()
}

// preprocess reads input from infile, closes fd of infile, and decode input if needed.
func preprocess(infile *os.File, decrypt bool, encoding gfc.Encoding) (gfc.Buffer, error) {
	// Read input from a file or stdin. If from stdin, a "\n" denotes the end of the input.
	var gfcInput gfc.Buffer = new(bytes.Buffer)
	if infile == os.Stdin {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		gfcInput = bytes.NewBuffer([]byte(scanner.Text()))
	} else {
		_, err := gfcInput.ReadFrom(infile)
		if err != nil {
			return nil, errors.Wrapf(err, "failed to read from input file: %s", infile.Name())
		}
	}

	// Only close non-stdin file
	if infile != os.Stdin {
		err := infile.Close()
		if err != nil {
			return nil, errors.Wrapf(err, "failed to close infile %s", infile.Name())
		}
	}

	var err error
	if decrypt {
		gfcInput, err = gfc.Decode(encoding, gfcInput)
		if err != nil {
			return nil, errors.Wrap(err, "decoding failed")
		}
	}
	return gfcInput, nil
}

func crypt(input gfc.Buffer, key []byte, decrypt bool, algo gfc.Algorithm, mode gfc.AlgoMode) (gfc.Buffer, error) {
	switch algo {
	case gfc.AlgoAES:
		return cryptAES(input, key, decrypt, mode)
	case gfc.AlgoRSA:
		return cryptRSA(input, key, decrypt, mode)
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

func postprocess(buf gfc.Buffer, decrypt bool, encoding gfc.Encoding) (gfc.Buffer, error) {
	if decrypt {
		return buf, nil
	}
	return gfc.Encode(encoding, buf)
}
