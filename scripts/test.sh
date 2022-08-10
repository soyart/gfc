#!/usr/bin/env bash

go run ./cmd/gfc aes -e b64 -i go.mod -k scripts/files/aes.key | go run ./cmd/gfc aes -e b64 -k scripts/files/aes.key -d -o /dev/null\
&& go run ./cmd/gfc aes -e hex -i go.mod -k scripts/files/aes.key | go run ./cmd/gfc aes -e hex -k scripts/files/aes.key -d -o /dev/null\
&& go run ./cmd/gfc aes -c -e hex -i go.mod -k scripts/files/aes.key | go run ./cmd/gfc aes -c -e hex -k scripts/files/aes.key -d -o /dev/null\
&& go run ./cmd/gfc aes -c -e b64 -i go.mod -k scripts/files/aes.key | go run ./cmd/gfc aes -c -e b64 -k scripts/files/aes.key -d -o /dev/null\
&& go run ./cmd/gfc aes -m ctr -i go.mod -k scripts/files/aes.key | go run ./cmd/gfc aes -m ctr -k scripts/files/aes.key -d -o /dev/null\
&& go run ./cmd/gfc aes -m ctr -i go.mod -k scripts/files/aes.key | go run ./cmd/gfc aes -m ctr -k scripts/files/aes.key -d -o /dev/null\
&& go run ./cmd/gfc aes -m ctr -i go.mod -k scripts/files/aes.key | go run ./cmd/gfc aes -m ctr -k scripts/files/aes.key -d -o /dev/null\
&& go run ./cmd/gfc aes -m ctr -i go.mod -k scripts/files/aes.key | go run ./cmd/gfc aes -m ctr -k scripts/files/aes.key -d -o /dev/null\
&& printf "AES tests passed\n";

go run ./cmd/gfc rsa --public-key="$(< ./scripts/files/pub.pem)" -i ./scripts/install.sh -e hex | go run ./cmd/gfc rsa -e hex --private-key="$(< ./scripts/files/pri.pem)" -d -o /dev/null\
&& go run ./cmd/gfc rsa --public-key="$(< ./scripts/files/pub.pem)" -i ./scripts/install.sh -e b64 | go run ./cmd/gfc rsa -e b64 --private-key="$(< ./scripts/files/pri.pem)" -d -o /dev/null\
&& export PRI=$(< scripts/files/pri.pem)\
&& export PUB=$(< scripts/files/pub.pem)\
&& go run ./cmd/gfc rsa -i ./scripts/install.sh -e hex | go run ./cmd/gfc rsa -e hex -d -o /dev/null\
&& go run ./cmd/gfc rsa -i ./scripts/install.sh -c -e hex | go run ./cmd/gfc rsa -c -e hex -d -o /dev/null\
&& go run ./cmd/gfc rsa -i ./scripts/install.sh -c -e b64 | go run ./cmd/gfc rsa -c -e b64 -d -o /dev/null\
&& printf "RSA tests passed\n"
