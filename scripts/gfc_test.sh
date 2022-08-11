#!/usr/bin/env bash

# This file is deprecated. It is only here for reference purpose, in case I want to rewrite gfc_gfc_cli_test.sh

# For yes/no prompt, and line breaks
# get it at gitlab.com/artnoi-staple/unix/sh-tools/bin/yn.sh

. "$(command -v yn.sh)";
. "$(command -v lb.sh)";

mkdir -p tmptest;
typeset -A name flag ext;

# If you dont want to run certain test functions,
# just prepend a comment (#) OR remove the 'function' keyword

# Tests will be run from top to bottom

function gcm_key() {
	name[gcm_key]='AES GCM (with keyfile)';
	flag[gcm_key]="-k ./assets/files/aes.key";
	ext[gcm_key]='.gcm.wkey';
}
function gcm_hex_key() {
	name[gcm_hex_key]='AES GCM (hex with keyfile)';
	flag[gcm_hex_key]="--encoding hex -k ./assets/files/aes.key";
	ext[gcm_hex_key]='.gcm.hex.wkey';
}
function gcm_b64_key() {
	name[gcm_b64_key]='AES GCM (Base64 with keyfile)';
	flag[gcm_b64_key]="--encoding b64 -k ./assets/files/aes.key";
	ext[gcm_b64_key]='.gcm.b64.wkey';
}
function gcm_compressed_key() {
	name[gcm_compressed_key]='AES GCM (with keyfile) compressed';
	flag[gcm_compressed_key]="-c -k ./assets/files/aes.key";
	ext[gcm_compressed_key]='.gcm.cmp.wkey';
}
function gcm_compressed_hex_key() {
	name[gcm_compressed_hex_key]='AES GCM (Hex with keyfile) compressed';
	flag[gcm_compressed_hex_key]="-c -encoding hex -k ./assets/files/aes.key";
	ext[gcm_compressed_hex_key]='.gcm.cmp.hex.wkey';
}
function gcm_compressed_b64_key() {
	name[gcm_compressed_b64_key]='AES GCM (Base64 with keyfile) compressed';
	flag[gcm_compressed_b64_key]="-c --encoding b64 -k ./assets/files/aes.key";
	ext[gcm_compressed_b64_key]='.gcm.cmp.b64.wkey';
}
function ctr_key() {
	name[ctr_key]='AES CTR (with keyfile)';
	flag[ctr_key]="-m CTR -k ./assets/files/aes.key";
	ext[ctr_key]+='.ctr.wkey';
}
function ctr_hex_key() {
	name[ctr_hex_key]='AES CTR (hex with keyfile)';
	flag[ctr_hex_key]="-m CTR --encoding hex -k ./assets/files/aes.key";
	ext[ctr_hex_key]+='.ctr.hex.wkey';
}
function ctr_b64_key() {
	name[ctr_b64_key]='AES CTR (Base64 with keyfile)';
	flag[ctr_b64_key]="-m CTR --encoding b64 -k ./assets/files/aes.key";
	ext[ctr_b64_key]+='.ctr.b64.wkey';
}
function ctr_compressed_key() {
	name[ctr_compressed_key]='AES CTR (with keyfile) compressed';
	flag[ctr_compressed_key]="-c -m CTR -k ./assets/files/aes.key";
	ext[ctr_compressed_key]+='.ctr.cmp.wkey';
}
function ctr_compressed_hex_key() {
	name[ctr_compressed_hex_key]='AES CTR (Hex with keyfile) compressed';
	flag[ctr_compressed_hex_key]="-c --encoding hex -m CTR -k ./assets/files/aes.key";
	ext[ctr_compressed_hex_key]+='.ctr.cmp.hex.wkey';
}
function ctr_compressed_b64_key() {
	name[ctr_compressed_b64_key]='AES CTR (Base64 with keyfile) compressed';
	flag[ctr_compressed_b64_key]="-c --encoding b64 -m CTR -k ./assets/files/aes.key";
	ext[ctr_compressed_b64_key]+='.ctr.cmp.b64.wkey';
}
function gcm() {
	name[gcm]='AES GCM (passphrase)';
	flag[gcm]="";
	ext[gcm]='.gcm';
}
function gcm_hex() {
	name[gcm_hex]='AES GCM (hex with passphrase)';
	flag[gcm_hex]="--encoding hex";
	ext[gcm_hex]='.gcm.hex';
}
function gcm_b64() {
	name[gcm_b64]='AES GCM (Base64 with passphrase)';
	flag[gcm_b64]="--encoding b64";
	ext[gcm_b64]='.gcm.b64';
}
function gcm_compressed() {
	name[gcm_compressed]='AES GCM (passphrase) compressed';
	flag[gcm_compressed]="-c";
	ext[gcm_compressed]='.gcm.cmp';
}
function gcm_compressed_hex() {
	name[gcm_compressed_hex]='AES GCM (Hex with passphrase) compressed';
	flag[gcm_compressed_hex]="-c";
	ext[gcm_compressed_hex]='.gcm.cmp.hex';
}
function gcm_compressed_b64() {
	name[gcm_compressed_b64]='AES GCM (Base64 passphrase) compressed';
	flag[gcm_compressed_b64]="-c --encoding b64";
	ext[gcm_compressed_b64]='.gcm.cmp.b64';
}
function ctr() {
	name[ctr]='AES CTR (passphrase)';
	flag[ctr]="-m CTR";
	ext[ctr]+='.ctr';
}
function ctr_hex() {
	name[ctr_hex]='AES CTR (hex with passphrase)';
	flag[ctr_hex]="-m CTR --encoding hex";
	ext[ctr_hex]+='.ctr.hex';
}
function ctr_b64() {
	name[ctr_b64]='AES CTR (Base64 with passphrase)';
	flag[ctr_b64]="-m CTR --encoding b64";
	ext[ctr_b64]+='.ctr.b64';
}
function ctr_compressed() {
	name[ctr_compressed]='AES CTR (passphrase) compressed';
	flag[ctr_compressed]="-c -m CTR";
	ext[ctr_compressed]+='.ctr.cmp';
}
function ctr_compressed_hex() {
	name[ctr_compressed_hex]='AES CTR (Hex with passphrase) compressed';
	flag[ctr_compressed_hex]="-c --encoding hex -m CTR";
	ext[ctr_compressed_hex]+='.ctr.cmp.hex';
}
function ctr_compressed_b64() {
	name[ctr_compressed_b64]='AES CTR (Base64 with passphrase) compressed';
	flag[ctr_compressed_b64]="-c --encoding b64 -m CTR";
	ext[ctr_compressed_b64]+='.ctr.cmp.b64';
}

if [[ -x gfc && ! -d gfc ]];
	then
	printf "WARN: Testing built binary not source\n";
	printf "To test source, remove file named 'gfc'\n";

	gfccmd='./gfc';
else
	gfccmd="go run ./cmd/gfc";
fi;

encsrc='assets/files/zeroes';
aeskey='assets/files/aes.key';
encdst0='tmptest/testgfc';
decdst0='tmptest/zeroes';

# RSA test
simyn "Run test RSA on file assets/files/aes.key with keys assets/files/pub.pem and assets/files/pri.pem?"\
&& pub="./assets/files/pub.pem"\
&& pri="./assets/files/pri.pem"\
&& printf "Testing RSA encryption (ENV)\n"\
&& [[ -f $pub || -f $pri ]]\
&& PUB=$(< $pub) sh -c "${gfccmd} rsa -i "${aeskey}" -o tmptest/rsaOut"\
&& printf "Testing RSA decryption (ENV)\n"\
&& PRI=$(< $pri) sh -c "${gfccmd} rsa -d -i tmptest/rsaOut -o tmptest/aes.key"\
&& printf "Testing equality\n"\
&& diff tmptest/aes.key assets/files/aes.key\
&& printf "✅ (ok) assets/files match\n"\
&& sh -c "${gfccmd} rsa --public-key $pub -i ${aeskey} -o tmptest/rsaOut"\
&& printf "Testing RSA decryption\n"\
&& sh -c "${gfccmd} rsa -d --private-key $pri -i tmptest/rsaOut -o tmptest/aes.key"\
&& printf "Testing equality\n"\
&& diff tmptest/aes.key "${aeskey}"\
&& printf "✅ (ok) file match\n"\
&& rm tmptest/rsaOut tmptest/aes.key\
|| printf "❌ (failed) assets/files differ\n";

line;

# AES test
# Get function names of this file from awk
functions=$(awk '/^function / {print substr($2, 1, length($2)-2)}' $0);
c=0 && for fun in ${functions[@]};
do
	((c++));

	"$fun"\
	&& name="${name[$fun]}"\
	&& encdst="${encdst0}${ext[$fun]}"\
	&& decsrc="${encdst}"\
	&& decdst="${decdst0}${ext[$fun]}"\
	&& alflag="${flag[$fun]}";
	
	simyn "\nRun test ${c} - ${name[$fun]}"\
	|| continue;

	# Encrypt, decrypt, and check diff
	sh -c "${gfccmd} aes -i ${encsrc} -o ${encdst} ${alflag}";
	sh -c "${gfccmd} aes -i ${decsrc} -o ${decdst} ${alflag} -d";
	diff $decdst $encsrc\
	&& printf "\n✅ (ok) files match:\n${decdst} == ${encdst}\n"\
	|| printf "\n❌ (failed) files differ:\n${decdst} xx ${encdst}\n";
	simyn "Finished test ${name}.\nRemove test files?"\
	&& rm -v "$encdst" "$decdst";
	line;
done;

simyn "All tests done. Remove all test files?"\
&& rm -v "$encdst0"* "$decdst0"*;
