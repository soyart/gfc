#!/usr/bin/env bash

# Local variables are snake_case, while script's global variables are all UPPERCASE.
# This file performs e2e tests on gfc, in addition to the Go unit tests.

function usage() {
    printf "usage: gfc_test_ng.sh <INFILE> [-v]\n"
    printf "Use -v flag for verbose output\n"
}

test -z "$1" && printf "Missing test file argument\n" && usage && exit 1;
INFILE="$1";

test -n "$2" && [ $2 == "-v" ] && VERBOSE=1 || VERBOSE=0;

function is_verbose() {
    test $VERBOSE -ne 0
}

# Source yn.sh and lb.sh.
. "$(command -v yn.sh)" || printf "%s\n" "error: missing yn.sh - get it from https://gitlab.com/artnoi/unix/-/tree/main/sh-tools/bin";
. "$(command -v lb.sh)" || printf "%s\n" "error: missing lb.sh - get it from https://gitlab.com/artnoi/unix/-/tree/main/sh-tools/bin";

TMPTEST="tmptest";
mkdir -p "${TEMPTEST}";

TEST_CMD="go run ./cmd/gfc";

# gfc-aes only
typeset -A AES_MODE_ENUMS;
AES_MODE_ENUMS["CTR"]="--mode CTR";
AES_MODE_ENUMS["GCM"]="--mode GCM";

# gfc-aes only
typeset -A SYMMESTRIC_KEY_ENUMS;
SYMMESTRIC_KEY_ENUMS["Passphrase"]="";
SYMMESTRIC_KEY_ENUMS["Keyfile"]="--key ./assets/files/aes.key";

typeset -A ENCODING_ENUMS;
ENCODING_ENUMS["NoEncoding"]=""
ENCODING_ENUMS["Hex"]="--encoding hex";
ENCODING_ENUMS["Base64"]="--encoding b64";

typeset -A COMPRESSION_ENUMS
COMPRESSION_ENUMS["NoCompress"]="";
COMPRESSION_ENUMS["Compress"]="--compress";

# file_test() runs 1 test with 1 output file. It accept 6 arguments for the test.
# it is used to print test info to screen as well as running the actual test,
# reporting the test result, and later performs cleanup operations.
function file_test() {
    # Argument list
    test_num=$1;
    test_desc=$2;
    enc_cmd=$3;
    dec_cmd=$4;
    enc_outfile=$5;
    dec_outfile=$6;

    is_verbose\
    && printf "[File Test] %s: %s\n" "${test_num}" "${test_desc}"\
    && echo ""\
    && printf "Encrypt command:\t%s\n" "${enc_cmd}"\
    && printf "Decrypt command:\t%s\n" "${dec_cmd}"\
    && printf "Encrypt outfile:\t%s\n" "${enc_outfile}"\
    && printf "Decrypt outfile:\t%s\n" "${dec_outfile}"\
    && echo "";

    simyn "[File Test] Run test ${test_num} ${test_desc}?"\
    && runtest=1\
    && sh -c "${enc_cmd}"\
    && sh -c "${dec_cmd}"\
    && diff "${INFILE}" "${dec_outfile}"\
    && printf "%s\n" "✅ OK: ${test_desc}"\
    || printf "%s\n" "❌ Failed: ${test_desc}";

    test $runtest -ne 0\
    && printf "[File Test] Cleaning up %s %s\n" "${enc_outfile}" "${dec_outfile}"\
    && rm ${enc_outfile} ${dec_outfile}\
    && printf "[File Test] %s\n" "✅ Cleanup successful"\
    || printf "[File Test] %s\n" "❌ Cleanup failed: ${test_desc}";

    line;
}

# Pipe tests must not receive keys (passphrases) from stdin.
# The pipe test command must be formatted beforehand by caller.
# Because pip tests make use of /dev/null to discard decryption output,
# I'm not sure if it'll work on Windows.
function pipe_test() {
    test_num="$1";
    test_desc="$2";
    pipe_test_cmd="$3";

    is_verbose\
    && printf "[Pipe Test] Piped command: %s\n" "${pipe_test_cmd}";

    simyn "[Pipe Test] Run test ${test_num} ${test_desc}?"\
    && sh -c "${pipe_test_cmd}"\
    && printf "[Pipe Test] %s\n" "✅ OK: ${test_desc}"\
    || printf "[Pipe Test] %s\n" "❌ Failed: ${test_desc}";

    line;
}

# rsa_test() loops over relevant enums for gfc-rsa and construct parameters for file_test() and pipe_test()
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

            test_desc="RSA test, encoding = ${encoding_test}, compresion = ${compression_test}";
            cmd="${TEST_CMD} rsa ${encoding_flag} ${compress_flag}";
            enc_cmd="${cmd} --public-key ${pubkey} -i ${INFILE} -o ${enc_outfile};";
            dec_cmd="${cmd} -d --private-key ${prikey} -i ${enc_outfile} -o ${dec_outfile};";

            file_test "$c" "$test_desc" "$enc_cmd" "$dec_cmd" "${enc_outfile}" "${dec_outfile}";

            pipe_test_cmd="${cmd} --public-key ${pubkey} -i ${INFILE} | ${cmd} -d --private-key ${prikey} -o /dev/null;";
            pipe_test "${test_num}" "${test_desc}" "${pipe_test_cmd}";
        done;
    done;
}

# aes_test() loops over relevant enums for gfc-aes and construct parameters for file_test() and pipe_test()
function aes_test() {
    for sym_key_test in ${!SYMMESTRIC_KEY_ENUMS[@]}; do
        for aes_mode_test in ${!AES_MODE_ENUMS[@]}; do
            for encoding_test in ${!ENCODING_ENUMS[@]}; do
                for compression_test in ${!COMPRESSION_ENUMS[@]}; do
                    ((c++));

                    aes_mode_flag=${AES_MODE_ENUMS[$aes_mode_test]};
                    aes_key_flag=${SYMMESTRIC_KEY_ENUMS[$sym_key_test]}
                    encoding_flag=${ENCODING_ENUMS[$encoding_test]};
                    compress_flag=${COMPRESSION_ENUMS[$compression_test]};

                    file_ext="${aes_mode_test}.${sym_key_test}.${encoding_test}.${compression_test}";
                    enc_outfile="${TMPTEST}/gfc_aes_test.${file_ext}.bin";
                    dec_outfile="${TMPTEST}/gfc_aes_test.${file_ext}.dec";

                    test_desc="AES test, mode = ${aes_mode_test}, key = ${sym_key_test}, encoding = ${encoding_test}, compresion = ${compression_test}";
                    cmd="${TEST_CMD} aes ${aes_mode_flag} ${aes_key_flag} ${encoding_flag} ${compress_flag}";
                    enc_cmd="${cmd} -i ${INFILE} -o ${enc_outfile};";
                    dec_cmd="${cmd} -d -i ${enc_outfile} -o ${dec_outfile};";

                    file_test "$c" "$test_desc" "$enc_cmd" "$dec_cmd" "${enc_outfile}" "${dec_outfile}";

                    # Skip pipe test if passphrase needs to be entered via stdin
                    [ "${sym_key_test}" = "Passphrase" ] && continue;

                    pipe_test_cmd="${cmd} -i ${INFILE} | ${cmd} -d -o /dev/null;"\
                    && pipe_test "${test_num}" "${test_desc}" "${pipe_test_cmd}";
                done;
            done;
        done;
    done;
}

# cc20_test loops over all relavant enums for gfc-cc20 and construct parameters for file_test() and pipe_test()
function cc20_test() {
    for sym_key_test in ${!SYMMESTRIC_KEY_ENUMS[@]}; do
        for encoding_test in ${!ENCODING_ENUMS[@]}; do
            for compression_test in ${!COMPRESSION_ENUMS[@]}; do
                ((c++));

                # Hard-coded
                prikey="assets/files/pri.pem";
                pubkey="assets/files/pub.pem";

                XChaCha20_key_flag=${SYMMESTRIC_KEY_ENUMS[$sym_key_test]}
                encoding_flag=${ENCODING_ENUMS[$encoding_test]};
                compress_flag=${COMPRESSION_ENUMS[$compression_test]};

                file_ext="${encoding_test}.${compression_test}";
                enc_outfile="${TMPTEST}/gfc_rsa_test.${file_ext}.bin";
                dec_outfile="${TMPTEST}/gfc_rsa_test.${file_ext}.dec";

                test_desc="XChaCha20 test, key = ${sym_key_test}, encoding = ${encoding_test}, compresion = ${compression_test}";
                cmd="${TEST_CMD} cc20 ${XChaCha20_key_flag} ${encoding_flag} ${compress_flag}";
                enc_cmd="${cmd} -i ${INFILE} -o ${enc_outfile};";
                dec_cmd="${cmd} -d -i ${enc_outfile} -o ${dec_outfile};";

                file_test "$c" "$test_desc" "$enc_cmd" "$dec_cmd" "${enc_outfile}" "${dec_outfile}";
                
                # Skip pipe test if passphrase needs to be entered via stdin
                [ "${sym_key_test}" = "Passphrase" ] && continue;
                
                pipe_test_cmd="${cmd} cc20 -i ${INFILE} | ${cmd} -d -o /dev/null;"\
                pipe_test "${test_num}" "${test_desc}" "${pipe_test_cmd}";
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

# XChaCha20Poly1305 tests
simyn "Test gfc-cc20?"\
&& c=0\
&& cc20_test;