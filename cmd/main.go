package main

import (
	"bufio"
	"bytes"
	"flag"
	"os"

	"github.com/artnoi43/gfc/pkg/lib/gfc"
)

/* Enum for encoding/decoding */
const (
	base64 = iota
	hex
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

/* Command-line flags are global */
var (
	f flags
)

func main() {
	f.parseFlags()
	output(crypt(input()))
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

func aesCrypt(ibuf gfc.Buffer) (aesOut gfc.Buffer) {
	var aesKey []byte
	/* Read AES keyfile - if empty, passphrase will be used */
	if f.usesAesKeyFile {
		aesKey = f.aesKeyFile.ReadKey()
	}
	switch f.aesMode {
	case "CTR", "ctr":
		if f.decrypt {
			aesOut = gfc.CTR_decrypt(ibuf, aesKey)
		} else {
			aesOut = gfc.CTR_encrypt(ibuf, aesKey)
		}
	case "GCM", "gcm":
		if f.decrypt {
			aesOut = gfc.GCM_decrypt(ibuf, aesKey)
		} else {
			aesOut = gfc.GCM_encrypt(ibuf, aesKey)
		}
	default:
		os.Stderr.Write([]byte("Invalid AES mode\n"))
		os.Exit(1)
	}
	return aesOut
}

func rsaCrypt(ibuf gfc.Buffer) (rsaOut gfc.Buffer) {
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
			rsaOut = gfc.RSA_decrypt(ibuf, priKey)
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
			rsaOut = gfc.RSA_encrypt(ibuf, pubKey)
		}
	}
	return rsaOut
}

func input() (ibuf gfc.Buffer) {
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
			ibuf = gfc.Decode(base64, ibuf)
		} else if f.usesHex {
			ibuf = gfc.Decode(hex, ibuf)
		}
	}
	/* Return (un)processed input buffer */
	return ibuf
}

func crypt(ibuf gfc.Buffer) (obuf gfc.Buffer) {
	if f.rsa {
		obuf = rsaCrypt(ibuf)
	} else {
		obuf = aesCrypt(ibuf)
	}
	/* Return encrypted/decrypted buffer */
	return obuf
}

func output(obuf gfc.Buffer) {
	/* Encode output when encrypting */
	if !f.decrypt {
		if f.usesBase64 {
			obuf = gfc.Encode(base64, obuf)
		} else if f.usesHex {
			obuf = gfc.Encode(hex, obuf)
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
