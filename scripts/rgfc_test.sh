#!/usr/bin/env sh

printf "%s\n" "You should run this script from . (i.e. in {GFC_REPO}/scripts)"

mkdir -p tmp;
SOURCE_DIR="files";
RGFC_OUT="tmp/files.bin";
TMP_SOURCE="tmp/${SOURCE_DIR}";

./rgfc.sh -e "${SOURCE_DIR}" "${RGFC_OUT}"\
&& cp -r "${SOURCE_DIR}" "${TMP_SOURCE}"\
&& ./rgfc.sh -d "${RGFC_OUT}"\
&& diff -r "${TMP_SOURCE}" "${SOURCE_DIR}"\
&& rm -r "$TMP_SOURCE" "${RGFC_OUT}";