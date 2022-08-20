#!/usr/bin/env bash

function copyfile() {
    cp -a gfc scripts/rgfc.sh ~/bin/.;
}

test  -f gfc \
&& copyfile\
|| go build -o gfc ./src/cmd/gfc\
&& copyfile;
