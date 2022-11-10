# gfc (go file crypt)

gfc is my first programming project, written the first day I learned Go. I intend to learn Go from its development, so expect some bad code.

gfc is a minimal encryption CLI tool designed to be versatile and easy to use. This package provides an executable (`cmd/gfc`), and a library (`pkg/gfc`) providing high-level wrapper for AES256-GCM, AES256-CTR, RSA256-OEAP, ChaCha20-Poly1305, XChaCha20-Poly1305.

gfc can encrypt any files which the user has read access to (except for RSA, which can only encrypt a small messages), as well as stdin.
## Features

- AES256-GCM and AES256-CTR encryption

- XChaCha20-Poly1305, and ChaCha20-Poly1305 encryption

- RSA-OEAP SHA512 encryption

- PBKDF2 passphrase hash derivation for symmetric cryptography

- ZSTD compression

- Hexadecimal or Base64 output

- Reads from files or stdin, and writes to files or stdout

The AES part of the code was first copied from [this source](https://levelup.gitconnected.com/a-short-guide-to-encryption-using-go-da97c928259f) for AES CTR, and [this source](https://gist.github.com/enyachoke/5c60f5eebed693d9b4bacddcad693b47) for AES GCM, although both files have changed so much since.

> ALERT: gfc stable just merged with commits that changed how final file layout is written, so if you have files encrypted with previous build of `gfc`, decrypt it with older versions, and re-encrypt plaintext with the current version.

## Using gfc as a Go library

Package [`github.com/artnoi43/gfc/pkg/gfc`](./pkg/gfc/) provides public functions for encrypting/decrypting and encoding/decoding.

> The data parameter to these cryptography functions is [`gfc.Buffer`](./pkg/gfc/buffer.go), which is quite constrained.
> In the [main program](./internal/cli/cli.go), `bytes.Buffer` is used as the standard way to pass data bytes around.
> This may be changed and the functions might just take `[]byte`.

## Using gfc as a program:

### Building gfc

Build `gfc` executable from source with `go build`:

    $ go build cmd/gfc  # compile gfc
    $ cp gfc ~/bin/.    # copy gfc to $PATH 

### Generating gfc encryption keys

#### Generating symmetric key for AES or ChaCha20 encryption

To generate a new AES key, I usually use `dd(1)` write 32 bytes of random character to a file:

    $ dd if=/dev/random of=assets/files/aes.key bs=32 count=1;

I'm too lazy to add deterministic keyfile hasher, so gfc will assume that the key is well randomized and can be used right away without PBKDF2 or SHA256 hash.

> In any cases, users should replace the test file `gfc/files/aes.key` included in this repository.

#### Generating RSA keypair for gfc with OpenSSL

First, you create a private key. In this case, it will be 4096-byte long with name `pri.pem`:

    $ openssl genrsa -out pri.pem 4096;

Then, derive a public key `pub.pem` from your private key `pri.pem`:

    $ openssl rsa -in pri.pem -outform PEM -pubout -out pub.pem;

## PBKDF2 key derivation function

Passphrases will be securely hashed using PBKDF2, which added random number _salt_ to the passphrase before SHA256 hashing is performed to ensure that the derived key will always be unique, even if the same passphrase is reused.

To decrypt files encrypted with key derived from a passphrase, that same _salt_ is needed in order to convert input passphrase into the key used to encrypt it in the first place.

Key and salt handling is in `pkg/gfc/pbkdf2.go`.

## Usage

### Defaults
Default infile: stdin

Default outfile: stdout

Default encryption mode:

- AES: AES256-GCM

- ChaCha20: XChaCha20-Poly1305

- RSA: RSA256-OEAP (only one is supported)

Default encoding: None

Default compression: None

Default key source (symmetric key cryptography only): Passphrase

### Help

gfc has 2 subcommands - `aes` for AES encryption, and `rsa` for RSA encryption. To see help for each subcommand, just run:

    $ gfc aes -h; # See help for gfc-aes
    $ gfc rsa -h; # See help for gfc-rsa
    $ gfc cc20 -h; # See help for gfc-cc20

### General arguments/flags

#### Input and output

`-i <INFILE>`, `--infile <INFILE>`, `-o <OUTFILE>`, and `--outfile <OUTFILE>` can be used to specify infile/outfile. If nothing is specified, stdin is used by default for input file, and stdout is used for output file.

    $ # Encrypt foo.txt with AES256-GCM to out.bin
    $ gfc aes -i foo.txt -o out.bin;

    $ # Encrypt foo.txt with AES256-GCM to stdout
    $ gfc aes -i foo.txt;

There're 2 ways to use stdin input - piping and by entering text manually.

    $ # gfc gets its input from pipe, and encrypts it with AES256-GCM
    $ curl https://artnoi.com | gfc aes -o artnoi.com.bin;
    
    $ # User types text input into stdin. The input ends with "\n".
    $ # The output is written to ./text.bin
    $ gfc aes --text -o text.bin;

#### Pre-encryption and post-encryption
> For more info on gfc pre-processing and post-processing, see [CLI page](/pkg/cli/)
##### Encoding
We can also apply some encoding to our output (encryption) or input (decryption) with `-e <ENCODING>` or `--encoding <ENCODING>`:

    $ # The first execution spits hex-encoded output to the other execution, which expects it
    $ gfc aes -i plain.txt -k mykey --encoding hex | gfc aes -d -k mykey --encoding hex;

##### Compression
Similar to encoding, we can enable ZSTD compression with flag `-c` or `--compress`. The example below combines ZSTD compression with hex encoding:

    $ gfc aes --compress -i plain.txt -k mykey -e hex | gfc aes --compress -d -k mykey -e hex;

#### Encryption key
##### AES and XChaCha20
In `gfc-aes` and `gfc-cc20`, we can specify key filename to use with `-k <KEYFILE>` or `--key <KEYFILE>`. The key must be 256-bit, i.e. 32-byte long. If the key argument is omitted, a user-supplied passphrase will be used to derive an encryption key using PDKDF2.

    $ # gfc will read key from ~/.secret/mykey and uses it to encrypt plain.txt to out.bin;
    $ gfc aes -k ~/.secret/mykey -i plain.txt -o out.bin;
    $
    $ # The same as above, but XChaCha20-Poly1305 is used
    $ gfc cc20 -k ~/.secret/mykey -i plain.txt -o out.bin;

##### RSA
It's quite tricky to specify RSA key in the command line, since the keypairs are usually long and multi-lined. As a result, we should leverage the power of UNIX shell to read keyfiles for us. The syntax for this is `"$(< FILENAME)"`, where the shell reads the file for us and gives us the content string.

RSA keyfiles can be specified in 2 ways - with environment variable or as a full flag:

    $ # The shell reads the content of file my_pub.pem to variable PUB
    $ export PUB="$(< my_pub.pem)";
    $
    $ # gfc uses the public key from ENV variable 'PUB' and uses it to encrypt plain.txt
    $ gfc rsa -i plain.txt -o out.bin;
    $ # The exact same thing as above, but key is given as argument instead
    $ gfc rsa -i plain.txt -o out.bin --public-key="$(< my_pub.pem)";


    $ # The shell reads the content of file my_pri.pem to variable PRI
    $ export PRI="$(< my_pri.pem)";
    $
    $ # gfc uses the public key from ENV variable 'PRI' and uses it to decrypt out.bin
    $ gfc rsa -d -i out.bin;
    $ # The exact same thing as above, but key is given as argument instead
    $ gfc rsa -d -i out.bin --private-key="$(< my_pri.pem)";

### Command examples

## Encrypting a directory

> Bash script `rgfc.sh` can be used to perform this task. Usage is simple; `$ rgfc.sh <dir> <outfile>` will first create temporary tarball from `<dir>`, and encrpyts the tarball. If the encryption is successful, the unencrypted tarball is removed.

gfc does not recursively encrypt/decrypt files - that would add needless complexity. If you are encrypting a directory (folder), use `tar(1)` to archive (and optionally compress) the directory, and use gfc to encrypt that tarball.

For example, to create Zstd compressed archive of directory _before encryption_ `foo`:

    $ tar --zstd -cf foo.zstd foo;

And extract it after decryption with:

    $ tar --zstd -xf foo.zstd;

Or with xz compression:

    $ tar -cJf foo.txz foo;
    $ tar -xJf foo.txz;

## Testing gfc

In addition to Go unit tests, Bash scripts `gfc_test.sh` is shipped with gfc and can be use to test a combination of commands.

## Repositories

There are 2 repositories for gfc, one on GitHub.com and one on GitLab.com

The main (stable) branch of gfc is hosted on [Github](https://github.com/artnoi43/gfc).

## Depedencies

I try my best to keep [dependencies](go.mod) low and aviod using external libraries.

imported for ZSTD compression

## License

This software is licensed under the MIT License.
