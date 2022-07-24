# Package `gfc`

Code in this package provides the core gfc functionality, e.g. I/O (`utils.go`), encryption/decryption (`gcm.go`, `ctr.go`, `rsa.go`). Cryptographic code is organized such that a file represents one algorithm, including its encrypt and decrypt functions.

gfc in general passes data around as function argument for the sake of simplicity. The data pipeline (in `main.go`) is:

    output(crypt(input()))

- `input()` reads data from a file

- `crypt()` encrypts/decrypts data from `input()`

- `output()` writes data returned from `crypt()` to a file

that is, the program first gets its input from any file (including stdin) with function `input()`, which then returns the read data to its caller `crypt()`, which encrypts/decrypts the input data and return processed data to its caller `output()`, which then writes the processed data to a file. The output file can be an actual file or stdout.

## Buffer
The `gfc` package uses its own custom interface `Buffer` (see `buffer.go`) to describe function parameters. I prefer this to both `[]byte` and `bytes.Buffer` because it gives me a sense of flexibility. With this interface, we can still use `bytes.Buffer` or any other structs that implement interface `Buffer`.

    // buffer.go
	type Buffer interface {
		Read([]byte) (int, error)
		Write([]byte) (int, error)
		ReadFrom(io.Reader) (int64, error)
		WriteTo(io.Writer) (int64, error)
	}

The 4 methods defined in the interface are meant to facilitate `main.go`'s `input()`, `crypt()`, and `output()`, as well as this package's `Encode` and `Decode`.
