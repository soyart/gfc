# Package `gfc`

Code in this package provides the core gfc functionality, e.g. I/O (`utils.go`), encryption/decryption (`gcm.go`, `ctr.go`, `rsa.go`), and byte encoding (`utils.go`). Cryptography code is organized such that a file represents one algorithm, including its encrypt and decrypt functions.

Users can import this package and use the functions defined here easily.

## AES encryption
All AES encryption functions derive key using PBKDF2 automatically. The default AES algorithm AES-GCM needs an Nonce (number once), which here is 96-bit (12-byte), and the alternative algorithm AES-CTR needs an IV (initiation vector), which in gfc is of size 128-bit (16-byte). Because PBKDF2 is used, it's important that the PBKDF2 salt is stored in the ciphertext, so that we can grab and use it during encryption. The ciphertext output format is:

    <Ciphertext> <GCM Nonce or CTR IV> <PBKDF2 Salt>

Salt is appended last, and during decryption, we need to extract the salt first in order to derive our PBKDF2 back from our raw key bytes. The index at which PBKDF2 salt starts is always the length of the ciphertext minus the salt length.

## Buffer
The `gfc` package uses its own custom interface `Buffer` (see `buffer.go`) to describe function parameters. I prefer this to both `[]byte` and `bytes.Buffer` because it gives me a sense of flexibility. With this interface, we can still use `*bytes.Buffer` or any other structs that implement interface `Buffer`.

    // buffer.go
	type Buffer interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		ReadFrom(io.Reader) (int64, error)
		WriteTo(io.Writer) (int64, error)
	}

The 4 methods defined in the interface are meant to facilitate `main.go`'s `input()`, `crypt()`, and `output()`, as well as this package's `Encode` and `Decode`.
