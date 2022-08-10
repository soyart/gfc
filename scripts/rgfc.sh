#!/usr/bin/env bash

# rgfc.sh -e mydir mydir.bin # Encryption
# rgfc.sh -d mydir.bin # Decryption -> will output mydir dir

TAR_VERSION="$(tar --version)";
printf "tar version: %s\n" "${TAR_VERSION}";

if [[ $TAR_VERSION == "bsdtar"* ]];
then
	TAR_FLAGS="tar -cJf"
	TARBALL_EXT=".tar.xz"
	UNTAR_FLAGS="tar -xJf"
else
	TAR_FLAGS="tar --zstd -cf"
	TARBALL_EXT=".tar.zst"
	UNTAR_FLAGS="tar -xf"
fi;

printf "tar command: %s\n" "${TAR_FLAGS}";
printf "un-tar command: %s\n" "${UNTAR_FLAGS}";

case "${1}" in
	"-e")
		INDIR="$2";
		OUTTARBIN="$3";
		TARBALL_COMPRESSED="${INDIR}${TARBALL_EXT}";
		# tar the dir first
		sh -c "${TAR_FLAGS} ${TARBALL_COMPRESSED} ${INDIR};"\
		&& sh -c "gfc aes -i ${TARBALL_COMPRESSED} -o ${OUTTARBIN};"\
		&& sh -c "rm ${TARBALL_COMPRESSED};";
	;;

	"-d")
		INTARBIN="$2";
		OUTDIR="$3"
		DECRYPTED_TARBALL="${INTARBIN}.decrypted${TARBALL_EXT}";
		UNTAR_CMD="${UNTAR_FLAGS} ${DECRYPTED_TARBALL} -C ${OUTDIR};";
		printf "UNTAR_CMD: %s\n" "${UNTAR_CMD}";
		sh -c "gfc aes -d -i ${INTARBIN} -o ${DECRYPTED_TARBALL};"\
		&& sh -c "${UNTAR_CMD}"\
		&& sh -c "rm ${DECRYPTED_TARBALL};";
	;;
esac;