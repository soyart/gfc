package gfc

type gfcError int

const (
	// Default
	NoError gfcError = iota
	// Error CTR new cipher
	ECTRNEWCIPHER
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

func (err gfcError) Error() string {
	switch err {
	case ECTRNEWCIPHER:
		return "CTR: New CTR"
	case ECTRREAD:
		return "CTR: Read Buffer"
	case EGCMNEWCIPHER:
		return "GCM: New cipher"
	case EGCMNEWGCM:
		return "GCM: New GCM"
	case EGCMOPEN:
		return "GCM: Open"
	case ERSAPARSEPUB:
		return "RSA: Parse Public Key"
	case ERSAENCR:
		return "RSA: Encrypt"
	case ERSAPARSEPRI:
		return "RSA: Parse Private Key"
	case ERSADECR:
		return "RSA: Decrypt"
	default:
		return "bad error - should not happen"
	}
}
