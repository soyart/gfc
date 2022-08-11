# Utility scripts
Some scripts in this directory are actually utilities:

- `rgfc.sh` uses `tar` and `gfc` to encrypt a directory.

- `install.sh` installs `gfc` and `rgfc.sh` to `$HOME/bin`.

- `new_aes_key.sh` and `new_rsa_key.sh` generate new AES/RSA key/keypair.

# Test scripts
gfc scripts are mostly Bash scripts for gfc development, including gfc CLI tests `gfc_test.sh` and `gfc_pipe_test.sh`.

- `gfc_test.sh` is the main test for gfc CLI behaviors.

- `gfc_pipe_test.sh` is used to test gfc reading from pipes.

- `rgfc_test.sh` is the test script for `rgfc.sh`.
