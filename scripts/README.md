# Utility scripts
Some scripts in this directory are actually utilities:

- `rgfc.sh` uses `tar` and `gfc` to encrypt a directory.

- `install.sh` installs `gfc` and `rgfc.sh` to `$HOME/bin`.

- `new_aes_key.sh` and `new_rsa_key.sh` generate new AES/RSA key/keypair.

# Test scripts
These scripts are used to test `gfc` or `rgfc.sh`:

- `gfc_test.sh` is the main test for gfc CLI behaviors.

- `rgfc_test.sh` is the test script for `rgfc.sh`.
