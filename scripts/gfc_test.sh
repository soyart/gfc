#!/usr/bin/env bash

function usage() {
    printf "usage: gfc_test_ng.sh <INFILE> [-v]\n"
    printf "Use -v flag for verbose output\n"
}

test -z "$1" && printf "Missing test file argument\n" && usage && exit 1;
INFILE="$1";

test -n "$2" && [ $2 == "-v" ] && VERBOSE=1 || VERBOSE=0;

# Source yn.sh and lb.sh.
. "$(command -v yn.sh)" || printf "%s\n" "error: missing yn.sh - get it from https://gitlab.com/artnoi/unix/-/tree/main/sh-tools/bin";
. "$(command -v lb.sh)" || printf "%s\n" "error: missing lb.sh - get it from https://gitlab.com/artnoi/unix/-/tree/main/sh-tools/bin";

TMPTEST="tmptest";
TEST_CMD="go run ./cmd/gfc"

# gfc-aes only
typeset -A AES_MODE_ENUMS;
AES_MODE_ENUMS["CTR"]="--mode CTR";
AES_MODE_ENUMS["GCM"]="--mode GCM";

# gfc-aes only
typeset -A AES_KEY_ENUMS;
AES_KEY_ENUMS["Passphrase"]="";
AES_KEY_ENUMS["Keyfile"]="--key ./assets/files/aes.key";

typeset -A ENCODING_ENUMS;
ENCODING_ENUMS["NoEncoding"]=""
ENCODING_ENUMS["Hex"]="--encoding hex";
ENCODING_ENUMS["Base64"]="--encoding b64";

typeset -A COMPRESSION_ENUMS
COMPRESSION_ENUMS["NoCompress"]="";
COMPRESSION_ENUMS["Compress"]="--compress";

# run_test() runs 1 test. It accept 6 arguments for the test.
# it is used to print test info to screen as well as running the actual test,
# reporting the test result, and later performs cleanup operations.
function run_test() {
    # Argument list
    test_num=$1;
    desc=$2;
    enc_cmd=$3;
    dec_cmd=$4;
    enc_outfile=$5;
    dec_outfile=$6;

    test $VERBOSE -ne 0\
    && printf "Test %s: %s\n" "${test_num}" "${desc}"\
    && echo ""\
    && printf "Encryption command:\t%s\n" "${enc_cmd}"\
    && printf "Decryption command:\t%s\n" "${dec_cmd}"\
    && printf "Encryption outfile:\t%s\n" "${enc_outfile}"\
    && printf "Decryption outfile:\t%s\n" "${dec_outfile}"\
    && echo "";

    simyn "Run test ${test_num} ${desc}"\
    && runtest=1\
    && sh -c "${enc_cmd}"\
    && sh -c "${dec_cmd}"\
    && diff "${INFILE}" "${dec_outfile}"\
    && printf "%s\n" "✅ OK: ${desc}"\
    || printf "%s\n" "❌ Failed: ${desc}";

    test $runtest -ne 0\
    && printf "Cleaning up %s %s\n" "${enc_outfile}" "${dec_outfile}"\
    && rm ${enc_outfile} ${dec_outfile}\
    && printf "%s\n" "✅ Cleanup successful"\
    || printf "%s\n" "❌ Cleanup failed: ${desc}";

    line;
}

# rsa_test() loops over relevant enums for gfc-rsa and construct parameters for run_test()
function rsa_test() {
    for encoding_test in ${!ENCODING_ENUMS[@]}; do
        for compression_test in ${!COMPRESSION_ENUMS[@]}; do
            ((c++));

            # Hard-coded
            prikey="assets/files/pri.pem";
            pubkey="assets/files/pub.pem";

            encoding_flag=${ENCODING_ENUMS[$encoding_test]};
            compress_flag=${COMPRESSION_ENUMS[$compression_test]};

            file_ext="${encoding_test}.${compression_test}";
            enc_outfile="${TMPTEST}/gfc_rsa_test.${file_ext}.bin";
            dec_outfile="${TMPTEST}/gfc_rsa_test.${file_ext}.dec";

            desc="RSA test, encoding = ${encoding_test}, compresion = ${compression_test}";
            cmd="${TEST_CMD} rsa ${encoding_flag} ${compress_flag}";
            enc_cmd="${cmd} --public-key ${pubkey} -i ${INFILE} -o ${enc_outfile};";
            dec_cmd="${cmd} -d --private-key ${prikey} -i ${enc_outfile} -o ${dec_outfile};";

            run_test "$c" "$desc" "$enc_cmd" "$dec_cmd" "${enc_outfile}" "${dec_outfile}";
        done;
    done;
}

# aes_test() loops over relevant enums for gfc-aes and construct parameters for run_test()
function aes_test() {
    for aes_key_test in ${!AES_KEY_ENUMS[@]}; do
        for aes_mode_test in ${!AES_MODE_ENUMS[@]}; do
            for encoding_test in ${!ENCODING_ENUMS[@]}; do
                for compression_test in ${!COMPRESSION_ENUMS[@]}; do
                    ((c++));

                    aes_mode_flag=${AES_MODE_ENUMS[$aes_mode_test]};
                    aes_key_flag=${AES_KEY_ENUMS[$aes_key_test]}
                    encoding_flag=${ENCODING_ENUMS[$encoding_test]};
                    compress_flag=${COMPRESSION_ENUMS[$compression_test]};

                    file_ext="${aes_mode_test}.${aes_key_test}.${encoding_test}.${compression_test}";
                    enc_outfile="${TMPTEST}/gfc_aes_test.${file_ext}.bin";
                    dec_outfile="${TMPTEST}/gfc_aes_test.${file_ext}.dec";

                    desc="AES test, mode = ${aes_mode_test}, key = ${aes_key_test}, encoding = ${encoding_test}, compresion = ${compression_test}";
                    cmd="${TEST_CMD} aes ${aes_mode_flag} ${aes_key_flag} ${encoding_flag} ${compress_flag}";
                    enc_cmd="${cmd} -i ${INFILE} -o ${enc_outfile};";
                    dec_cmd="${cmd} -d -i ${enc_outfile} -o ${dec_outfile};";

                    run_test "$c" "$desc" "$enc_cmd" "$dec_cmd" "${enc_outfile}" "${dec_outfile}";
                done;
            done;
        done;
    done;
}

# RSA tests
printf "Caution: RSA is a public key cryptographic algorithm - it can only encrypt a short length message\n"\
&& simyn "Test gfc-rsa?"\
&& c=0\
&& rsa_test;

# AES tests
simyn "Test gfc-aes?"\
&& c=0\
&& aes_test;