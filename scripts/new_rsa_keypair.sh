#!/usr/bin/env bash
openssl genrsa -out pri.pem 4096;
openssl rsa -in pri.pem -outform PEM -pubout -out pub.pem;