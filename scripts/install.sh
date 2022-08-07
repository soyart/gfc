#!/bin/sh

function copyfile() {
    cp -a gfc scripts/rgfc.sh ~/bin/.;
}

[  -f gfc ]\
&& copyfile\
|| go build -o gfc ./cmd/gfc\
&& copyfile;