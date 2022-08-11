#!/usr/bin/env bash

function usage() {
    printf "usage: new_aes_key.sh <OUTFILE>\n";
    printf "example: new_aes_key.sh myaeskey.key\n";
}

test -z "$1" && printf "error: expecting 1 argument\n" && usage && exit 1;
OUTFILE="$1"

printf "Writing new AES key to %s\n" "${OUTFILE}";
dd if=/dev/random of="${OUTFILE}" bs=32 count=1;