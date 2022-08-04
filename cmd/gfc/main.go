package main

import (
	"bufio"
	"bytes"
	"flag"
	"os"

	"github.com/artnoi43/gfc/pkg/lib/gfc"
)

/* Command-line flags */
type flags struct {
	decrypt             bool
	rsa                 bool
	usesAesKeyFile      bool
	stdin, stdout       bool
	usesBase64, usesHex bool // If both, use Base64. See input() and output()
	aesMode             string
	infile, outfile     gfc.File
	aesKeyFile          gfc.KeyFile
	pubFile, priFile    gfc.KeyFile
}

func main() {
	f := new(flags)
	f.parseFlags()
	output(crypt(input(f)))
}

func (f *flags) parseFlags() {
	flag.BoolVar(&f.decrypt, "d", false, "Decrypt")
	flag.BoolVar(&f.rsa, "rsa", false, "Use RSA encryption")
	flag.BoolVar(&f.usesAesKeyFile, "k", false, "Use key file for AES")
	flag.BoolVar(&f.stdin, "stdin", false, "Get input from stdin")
	flag.BoolVar(&f.stdout, "stdout", false, "Direct output to stdout")
	flag.BoolVar(&f.usesBase64, "B", false, "Base64 encoding/decoding")
	flag.BoolVar(&f.usesHex, "H", false, "Hexadecimal encoding/decoding")
	flag.StringVar(&f.aesMode, "m", "GCM", "AES modes (GCM or CTR)")
	flag.StringVar(&f.infile.Name, "i", "", "Input file")
	flag.StringVar(&f.outfile.Name, "o", "/tmp/delete.me", "Output file")
	flag.StringVar(&f.aesKeyFile.Name, "f", "dev/aes.key", "AES key file")
	flag.StringVar(&f.pubFile.Name, "pub", "", "RSA public key file")
	flag.StringVar(&f.priFile.Name, "pri", "", "RSA private key file")

	flag.Parse()
}

// aesCrypt prepares key for AES and calls the AES encryption/decryption functions
func aesCrypt(f *flags, ibuf gfc.Buffer) (aesOut gfc.Buffer) {
	var aesKey []byte
	var err error
	/* Read AES keyfile - if empty, passphrase will be used */
	if f.usesAesKeyFile {
		aesKey = f.aesKeyFile.ReadKey()
	}
	switch f.aesMode {
	case "CTR", "ctr":
		if f.decrypt {
			aesOut, err = gfc.DecryptCTR(ibuf, aesKey)
		} else {
			aesOut, err = gfc.EncryptCTR(ibuf, aesKey)
		}
	case "GCM", "gcm":
		if f.decrypt {
			aesOut, err = gfc.DecryptGCM(ibuf, aesKey)
		} else {
			aesOut, err = gfc.EncryptGCM(ibuf, aesKey)
		}
	default:
		os.Stderr.Write([]byte("Invalid AES mode - only GCM or CTR is supported\n"))
		os.Exit(1)
	}
	if err != nil {
		os.Stderr.WriteString("AES crypt error: " + err.Error())
	}
	return aesOut
}

// rsaCrypt prepares the RSA keypair and calls RSA encryption/decryption functions
func rsaCrypt(f *flags, ibuf gfc.Buffer) (rsaOut gfc.Buffer) {
	var err error
	if f.decrypt {
		var priKey []byte
		if f.usesAesKeyFile {
			priKey = f.priFile.ReadKey()
		} else {
			priKey = []byte(os.Getenv("RSA_PRI_KEY"))
		}
		switch len(priKey) {
		case 0:
			os.Stderr.Write([]byte(ERR_NO_PRI))
			os.Exit(1)
		default:
			rsaOut, err = gfc.DecryptRSA(ibuf, priKey)
		}
	} else {
		var pubKey []byte
		if f.usesAesKeyFile {
			pubKey = f.pubFile.ReadKey()
		} else {
			pubKey = []byte(os.Getenv("RSA_PUB_KEY"))
		}
		switch len(pubKey) {
		case 0:
			os.Stderr.Write([]byte(ERR_NO_PUB))
			os.Exit(1)
		default:
			rsaOut, err = gfc.EncryptRSA(ibuf, pubKey)
		}
	}
	if err != nil {
		os.Stderr.WriteString("RSA crypt error: " + err.Error())
	}
	return rsaOut
}

func input(f *flags) (*flags, gfc.Buffer) {
	var ibuf gfc.Buffer
	/* Read from stdin or file */
	if f.stdin {
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		ibuf = bytes.NewBuffer([]byte(scanner.Text()))
	} else {
		ibuf = f.infile.ReadFile()
	}
	/* Decode input when decrypting */
	if f.decrypt {
		if f.usesBase64 {
			ibuf = gfc.Decode(gfc.Base64, ibuf)
		} else if f.usesHex {
			ibuf = gfc.Decode(gfc.Hex, ibuf)
		}
	}
	/* Return (un)processed input buffer */
	return f, ibuf
}

func crypt(f *flags, ibuf gfc.Buffer) (*flags, gfc.Buffer) {
	var obuf gfc.Buffer
	if f.rsa {
		obuf = rsaCrypt(f, ibuf)
	} else {
		obuf = aesCrypt(f, ibuf)
	}
	/* Return encrypted/decrypted buffer */
	return f, obuf
}

func output(f *flags, obuf gfc.Buffer) {
	/* Encode output when encrypting */
	if !f.decrypt {
		if f.usesBase64 {
			obuf = gfc.Encode(gfc.Base64, obuf)
		} else if f.usesHex {
			obuf = gfc.Encode(gfc.Hex, obuf)
		}
	}
	var outfile *os.File
	/* Write to stdout or file */
	if f.stdout {
		outfile = os.Stdout
	} else {
		outfile = f.outfile.Create()
	}
	obuf.WriteTo(outfile)
}

const (
	ERR_NO_PUB = "No public key specified\nUse '-k -pub <path>', or environment variable RSA_PUB_KEY to specify RSA public key\n"
	ERR_NO_PRI = "No private key specified\nUse '-k -pri <path>', or environment variable RSA_PRI_KEY to specify RSA private key\n"
)
