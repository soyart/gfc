#!/usr/bin/env bash
printf "Writing out keys ./pri.pem and ./pub.pem\n";
openssl genrsa -out pri.pem 4096;
openssl rsa -in pri.pem -outform PEM -pubout -out pub.pem;