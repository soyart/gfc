package gfc

type (
	Encoding  uint8
	Algorithm uint8
	AlgoMode  uint8
)

// Avoid collisions by declaring them in 1 block
const (
	AlgoInvalid Algorithm = iota
	AlgoAES
	AlgoRSA
	AlgoXChaCha20

	ModeInvalid AlgoMode = iota
	ModeAesGCM
	ModeAesCTR
	ModeRsaOEAP
	ModeXChaCha20Poly1305
	ModeChaCha20Poly1305

	EncodingNone Encoding = iota
	EncodingBase64
	EncodingHex
)
