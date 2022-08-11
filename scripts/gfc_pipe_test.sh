#!/usr/bin/env bash

AES_INFILE="go.mod";
AES_KEYFILE="assets/files/aes.key";

# RSA can only decrypt small length message.
RSA_INFILE="./scripts/install.sh"
RSA_PRIKEYFILE="./assets/files/pri.pem";
RSA_PUBKEYFILE="./assets/files/pub.pem";

function missing() {
    test -n "$1" && missing_files="$1" || missing_files = "files"
    printf "missing %s\n" "${missing_files}"
    exit 1
}

test -f ${AES_INFILE} && test -f ${AES_KEYFILE} || missing "AES files";
test -f ${RSA_INFILE} && test -f ${RSA_PRIKEYFILE} && test -f ${RSA_PUBKEYFILE} || missing "RSA files";

go run ./cmd/gfc aes -e b64 -i "${AES_INFILE}" -k "${AES_KEYFILE}" | go run ./cmd/gfc aes -e b64 -k "${AES_KEYFILE}" -d -o /dev/null\
&& go run ./cmd/gfc aes -e hex -i "${AES_INFILE}" -k "${AES_KEYFILE}" | go run ./cmd/gfc aes -e hex -k "${AES_KEYFILE}" -d -o /dev/null\
&& go run ./cmd/gfc aes -c -e hex -i "${AES_INFILE}" -k "${AES_KEYFILE}" | go run ./cmd/gfc aes -c -e hex -k "${AES_KEYFILE}" -d -o /dev/null\
&& go run ./cmd/gfc aes -c -e b64 -i "${AES_INFILE}" -k "${AES_KEYFILE}" | go run ./cmd/gfc aes -c -e b64 -k "${AES_KEYFILE}" -d -o /dev/null\
&& go run ./cmd/gfc aes -m ctr -i "${AES_INFILE}" -k "${AES_KEYFILE}" | go run ./cmd/gfc aes -m ctr -k "${AES_KEYFILE}" -d -o /dev/null\
&& go run ./cmd/gfc aes -m ctr -i "${AES_INFILE}" -k "${AES_KEYFILE}" | go run ./cmd/gfc aes -m ctr -k "${AES_KEYFILE}" -d -o /dev/null\
&& go run ./cmd/gfc aes -m ctr -i "${AES_INFILE}" -k "${AES_KEYFILE}" | go run ./cmd/gfc aes -m ctr -k "${AES_KEYFILE}" -d -o /dev/null\
&& go run ./cmd/gfc aes -m ctr -i "${AES_INFILE}" -k "${AES_KEYFILE}" | go run ./cmd/gfc aes -m ctr -k "${AES_KEYFILE}" -d -o /dev/null\
&& printf "AES tests passed\n";

go run ./cmd/gfc rsa --public-key "${RSA_PUBKEYFILE}" -i ${RSA_INFILE} -e hex | go run ./cmd/gfc rsa -e hex --private-key="${RSA_PRIKEYFILE}" -d -o /dev/null\
&& go run ./cmd/gfc rsa --public-key "${RSA_PUBKEYFILE}" -i ${RSA_INFILE} -e b64 | go run ./cmd/gfc rsa -e b64 --private-key="${RSA_PRIKEYFILE}" -d -o /dev/null\
&& printf "RSA (key files as flags) passed\n";

export PRI="$(< ${RSA_PRIKEYFILE})"\
&& export PUB=$(< ${RSA_PUBKEYFILE})\
&& go run ./cmd/gfc rsa -i "${RSA_INFILE}" -e hex | go run ./cmd/gfc rsa -e hex -d -o /dev/null\
&& go run ./cmd/gfc rsa -i "${RSA_INFILE}" -c -e hex | go run ./cmd/gfc rsa -c -e hex -d -o /dev/null\
&& go run ./cmd/gfc rsa -i "${RSA_INFILE}" -c -e b64 | go run ./cmd/gfc rsa -c -e b64 -d -o /dev/null\
&& printf "RSA tests (keys read to ENVs) passed\n"
