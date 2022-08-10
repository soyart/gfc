# Package `cli`
This package is the CLI implementation of gfc. The main implementation is in `cli.go`.
## gfc subcommands
gfc is designed as a command-line program with *subcommands* similar to how `git` has `git add` and `git commit`. In gfc, a subcommand is a cryptographic algorithm. Currently, 2 are available (`gfc aes` and `gfc rsa`). Two add a new subcommand, just create a new struct that implements `Command` interface defined in `cli.go`.

The new struct can make use of `baseCryptFlags`, which represents shared command-line flags for encryption/decryption across all gfc crypto algorithms.

## `cli.go`
It first defines a `Command` interface, which all subcommands must implement. It is built around package `github.com/alexflint/go-arg`, where struct `Args` (defined in `args.go`) has other subcommands as fields. `Args.Handle` is used to *handle* the program flow.
### `Args.Handle`
Regardless of the subcommands, gfc starts by validating that all parameters it received are both valid and usable (if it's a file, then gfc must be able to open it on a filesystem, etc).

After that, it reads bytes from `infile` to memory using `readInput`. Then, it calls `preProcess`, which transforms the input based on flags provided by the user. An example of pre-processing is compressing the input bytes when encrypting, or decoding the base64-encoded input when decrypting.

If pre-processing went well, the function moves on to call `crypt`, which handles cryptography in gfc. The input is encrypted/decrypted based on the command-line flags. This cryptography output is then *post-processed* by `postProcess`, which again, transform the bytes according to user CLI flags.

The crypto output maybe encoded to hex or base64 (encryption with encoding), or decompressed into plaintext if it was compressed during encryption (decrypting the pre-compressed ciphertext).

How data flows from the input state to the output state can is shown here

![alt text](https://github.com/artnoi43/gfc/blob/develop/assets/excalidraw/handle.png?raw=true)