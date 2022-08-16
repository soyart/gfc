package gfc

type (
	Encoding  uint8
	Algorithm uint8
	AlgoMode  uint8

	CryptFunc func(Buffer, []byte) (Buffer, error)
)

// Avoid collisions by declaring them in 1 block
const (
	InvalidAlgorithm Algorithm = iota
	AlgoAES
	AlgoRSA
	AlgoXChaCha20

	InvalidAlgoMode AlgoMode = iota
	AES_GCM
	AES_CTR
	RSA_OEAP
	XChaCha20_Poly1305
	ChaCha20_Poly1305

	NoEncoding Encoding = iota
	EncodingBase64
	EncodingHex
)
