package gfc

type gfcError int

const (
	// Default
	NoError gfcError = iota
	// Error PBDKF2 key and salt derivation
	ErrPBKDF2KeySalt
	// Error unmarshaling gfc symmetric key output
	ErrUnmarshalSymmAEAD
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
	case ErrPBKDF2KeySalt:
		return "PBDKF2 error: key and salt"

	case ErrUnmarshalSymmAEAD:
		return "error: failed to unmarshal gfc symmetric key cryptography output"

	case ErrInvalidaes256BitKeyFileLen:
		return "PBKDF2 error: invalid keyfile length"

	case ErrNewCipherCTR:
		return "AES-CTR error: new CTR"

	case ErrReadCTR:
		return "AES-CTR error: read Buffer"

	case ErrNewCipherGCM:
		return "AES-GCM error: new cipher"

	case ErrNewGCM:
		return "AES-GCM error: new GCM"

	case ErrOpenGCM:
		return "AES-GCM error: open"

	case ErrParsePubRSA:
		return "RSA error: parse public key"

	case ErrEncryptRSA:
		return "RSA error: encrypt"

	case ErrParsePriRSA:
		return "RSA error: parse Private Key"

	case ErrDecryptRSA:
		return "RSA error: decrypt"

	case ErrNewCipherXChaCha20Poly1305:
		return "XChaCha20-Poly1305/ChaCha20-Poly1305 error: new cipher"

	case ErrOpenXChaCha20Poly1305:
		return "XChaCha20-Poly1305/ChaCha20-Poly1305 error: decrypt"

	}

	return "bad error - should not happen"
}
