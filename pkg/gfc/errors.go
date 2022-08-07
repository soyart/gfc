package gfc

type gfcError int

const (
	// Default
	NoError gfcError = iota
	// Error invalid keyfile length (32 bytes)
	ErrInvalidKeyfileLen
	// Error CTR new cipher
	ErrNewCipherCTR
	// Error CTR in read loop
	ErrReadCTR
	// Error GCM new cipher
	ErrNewCipherGCM
	// Error GCM new GCM
	ErrNewGCM
	// Error GCM open
	ErrOpenGCM
	// Error RSA parse pubkey
	ErrParsePubRSA
	// Error RSA encrypt
	ErrEncryptRSA
	// Error RSA pase prikey
	ErrParsePriRSA
	// Error RSA decrypt
	ErrDecryptRSA
)

func (err gfcError) Error() string {
	switch err {
	case ErrInvalidKeyfileLen:
		return "PBKDF2: Invalid keyfile length"
	case ErrNewCipherCTR:
		return "CTR: New CTR"
	case ErrReadCTR:
		return "CTR: Read Buffer"
	case ErrNewCipherGCM:
		return "GCM: New cipher"
	case ErrNewGCM:
		return "GCM: New GCM"
	case ErrOpenGCM:
		return "GCM: Open"
	case ErrParsePubRSA:
		return "RSA: Parse Public Key"
	case ErrEncryptRSA:
		return "RSA: Encrypt"
	case ErrParsePriRSA:
		return "RSA: Parse Private Key"
	case ErrDecryptRSA:
		return "RSA: Decrypt"
	default:
		return "bad error - should not happen"
	}
}
