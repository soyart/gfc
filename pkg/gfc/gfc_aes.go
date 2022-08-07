package gfc

// This file deines AES settings for gfc, like IV length for CTR mode and Nonce length for GCM mode.

const (
	lenNonceGCM int = 12 // 96-bit nonce for AES256-GCM
	// lenIVCTR    int = 16 // 128-bit IV for AES256-CTR - this is not hard-coded but instead derived from CTR block size.
)
