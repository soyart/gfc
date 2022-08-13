package gfc

type gfcError int

const (
	// Default
	NoError gfcError = iota
	// Error PBDKF2 key and salt derivation
	ErrPBKDF2KeySalt
	// Error invalid keyfile length (32 bytes)
	ErrInvalidaes256BitKeyFileLen
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
	// Error XChaCha20Poly1305 New cipher
	ErrNewCipherXChaCha20Poly1305
	// Error XChaCha20Poly1305 Open
	ErrOpenXChaCha20Poly1305
)

func (err gfcError) Error() string {
	switch err {
	case ErrInvalidaes256BitKeyFileLen:
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
	case ErrNewCipherXChaCha20Poly1305:
		return "XChaCha20Poly1305: New cipher"
	case ErrOpenXChaCha20Poly1305:
		return "XChaCha20Poly1305: Decrypt"
	default:
		return "bad error - should not happen"
	}
}
