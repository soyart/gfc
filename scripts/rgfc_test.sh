#!/usr/bin/env sh

printf "%s\n" "You should run this script from the project root";

WORK_DIR="tmptest"; # Base directory for testing (will be ignored by git)
PATH_TO_SOURCE_DIR="assets";
SOURCE_DIR="files"; # Test files
FULL_SOURCE_DIR_PATH="${PATH_TO_SOURCE_DIR}/${SOURCE_DIR}";
SOURCE_COPY="${WORK_DIR}/${SOURCE_DIR}"; # A copy of test files
RGFC_OUT="${WORK_DIR}/files.bin"; # Outfile name
OUTDIR="${WORK_DIR}/outbin.d";

printf "SOURCE_DIR %s SOURE_COPYC %s RGFC_OUT %s\n" "${SOURCE_DIR}" "${SOURE_COPYC}" "${RGFC_OUT}";
mkdir -p "${WORK_DIR}" ${OUTDIR};

COPY_CMD="cp -r ${FULL_SOURCE_DIR_PATH} ${SOURCE_COPY}";
ENC_CMD="./scripts/rgfc.sh -e ${SOURCE_COPY} ${RGFC_OUT}";
DEC_CMD="./scripts/rgfc.sh -d ${RGFC_OUT} ${OUTDIR}";
DIFF_CMD="diff -r ${OUTDIR}/${SOURCE_COPY} ${FULL_SOURCE_DIR_PATH}";
printf "COPY_CMD: '%s'\nENC_CMD: '%s'\nDEC_CMD: '%s'\nOUTDIR: '%s'\nDIFF_CMD: '%s'\n" "$COPY_CMD" "${ENC_CMD}" "${DEC_CMD}" "${OUTDIR}" "${DIFF_CMD}";

sh -c "${COPY_CMD}"\
&& sh -c "${ENC_CMD}"\
&& sh -c "${DEC_CMD}"\
&& sh -c "${DIFF_CMD}"\
&& printf "\n\nrgfc_test.sh: Ok\n";

rm -r "${WORK_DIR}";