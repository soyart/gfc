# Package `gfc`

Code in this package provides the core gfc functionality, e.g. I/O (`utils.go`), byte encoding (`encoding.go`), and the cryptography code. Cryptography code is organized such that a file represents one algorithm, including its encrypt and decrypt functions.

Users can import this package and use the functions defined here easily.

## Buffer
The `gfc` package uses its own custom interface `Buffer` (see `buffer.go`) to describe function parameters. It is usually a `bytes.Buffer`.

```go
// File buffer.go
type Buffer interface {
  Read([]byte) (int, error)
  Write([]byte) (int, error)
  ReadFrom(io.Reader) (int64, error)
  WriteTo(io.Writer) (int64, error)
  Len() int
  Bytes() []byte
}
```

## gfc's custom symmetric encryption output
**All symmetric encryption functions derive key using PBKDF2 automatically**. This requires us to store the `salt` in the encrypted output, so that the salt used during KDF when decrypting the message later. In addition to PBKDF2 salt, we will also have to store the nonce (number-once). The ciphertext output format is:

```
<Ciphertext> <Cipher Nonce> <PBKDF2 Salt>
```

> TODO: This output format is currently implemented as a structure. Maybe we'll add struct `symmOut` so that all gfc output from all symmetric key encryption algorithms are standardized. It is currently handled by `marshalSymmOut` and `unmarshalSymmOut`.

`PBKDF2 Salt` is fixed in gfc, at length of 32-byte.

`Cipher Nonce` size is different for each cipher:

- AES256-GCM: 12-byte

- AES256-CTR: 16-byte

- ChaCha20-Poly1305: 12-byte

- XChaCha20-Poly1305: 24-byte

During decryption, we need to extract the salt first in order to derive our PBKDF2 back from our raw key bytes. The index at which PBKDF2 salt starts is always the length of the ciphertext minus the salt length.
