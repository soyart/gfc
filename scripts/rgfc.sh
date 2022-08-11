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
		indir="$2";
		out_tar_bin="$3";
		tarball_compressed="${indir}${TARBALL_EXT}";
		# tar the dir first
		sh -c "${TAR_FLAGS} ${tarball_compressed} ${indir};"\
		&& sh -c "gfc aes -i ${tarball_compressed} -o ${out_tar_bin};"\
		&& sh -c "rm ${tarball_compressed};";
	;;

	"-d")
		intar_bin="$2";
		outdir="$3"
		decrypted_tarball="${intar_bin}.decrypted${TARBALL_EXT}";
		untar_cmd="${UNTAR_FLAGS} ${decrypted_tarball} -C ${outdir};";
		printf "untar_cmd: %s\n" "${untar_cmd}";
		sh -c "gfc aes -d -i ${intar_bin} -o ${decrypted_tarball};"\
		&& sh -c "${untar_cmd}"\
		&& sh -c "rm ${decrypted_tarball};";
	;;
esac;