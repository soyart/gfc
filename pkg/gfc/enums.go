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

	InvalidAlgoMode AlgoMode = iota
	AES_GCM
	AES_CTR
	RSA_OEAP

	NoEncoding Encoding = iota
	Base64
	Hex
)
