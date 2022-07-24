package gfc

import "os"

const (
	// Error CTR new cipher
	ECTRNEWCIPHER = iota + 1
	// Error CTR in read loop
	ECTRREAD
	// Error GCM new cipher
	EGCMNEWCIPHER
	// Error GCM new GCM
	EGCMNEWGCM
	// Error GCM open
	EGCMOPEN
	// Error RSA parse pubkey
	ERSAPARSEPUB
	// Error RSA encrypt
	ERSAENCR
	// Error RSA pase prikey
	ERSAPARSEPRI
	// Error RSA decrypt
	ERSADECR
)

func HandleErr(err int) {
	if err != 0 {
		switch err {
		case ECTRNEWCIPHER:
			os.Stderr.Write([]byte("Error: CTR: New CTR\n"))
		case ECTRREAD:
			os.Stderr.Write([]byte("Error: CTR: Read Buffer\n"))
		case EGCMNEWGCM:
			os.Stderr.Write([]byte("Error: GCM: New GCM\n"))
		case EGCMOPEN:
			os.Stderr.Write([]byte("Error: GCM: Open\n"))
		case ERSAPARSEPUB:
			os.Stderr.Write([]byte("Error: RSA: Parse Public Key\n"))
		case ERSAENCR:
			os.Stderr.Write([]byte("Error: RSA: Encrypt\n"))
		case ERSAPARSEPRI:
			os.Stderr.Write([]byte("Error: RSA: Parse Private Key\n"))
		case ERSADECR:
			os.Stderr.Write([]byte("Error: RSA: Decrypt\n"))
		}
		os.Exit(2)
	}
}