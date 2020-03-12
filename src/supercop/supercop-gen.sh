#!/bin/sh
#
# Generates SUPERCOP-style source trees for use with benchmarking suites.
#
# Usage: ./supercop-gen.sh tag
#
# Where "tag" is a name to use to distinguish these implementations from
# others like "ref" and "opt32" from other contributors.

if test -z "$1"; then
    echo "Usage: $0 tag"
    exit 1
fi
TAG="$1"

KAT_GEN=../../test/kat/kat-gen

SRC_DIR=../individual
OUT_DIR=./out
mkdir -p "$OUT_DIR"

# Remove the previous contents of the output directory.
rm -rf "$OUT_DIR"/*

# Generate the code for the AEAD algorithms.
for info_file in *aead ; do
    # Load the algorithm properties from the *.info file.
    unset aead_family
    unset aead_name
    unset aead_meta_name
    unset aead_srcdir
    unset aead_key_size
    unset aead_nonce_size
    unset aead_tag_size
    unset aead_encrypt
    unset aead_decrypt
    unset aead_exclude
    unset aead_header
    unset aead_kat_options
    . ./$info_file
    echo $info_file

    # Create the directory structure for the algorithm.
    AEAD_OUT_DIR="$OUT_DIR/$aead_family/Implementations/crypto_aead/$aead_name/$TAG"
    mkdir -p "$AEAD_OUT_DIR"

    # Copy the source files that make up the algorithm.
    cp "$SRC_DIR/$aead_srcdir"/*.[ch] "$AEAD_OUT_DIR"
    if test -n "$aead_exclude" ; then
        for exclude in $aead_exclude ; do
            rm -f "$AEAD_OUT_DIR/$exclude"
        done
    fi

    # Generate the api.h file with the algorithm properties.
    echo "#define CRYPTO_KEYBYTES $aead_key_size" >"$AEAD_OUT_DIR/api.h"
    echo "#define CRYPTO_NSECBYTES 0 " >>"$AEAD_OUT_DIR/api.h"
    echo "#define CRYPTO_NPUBBYTES $aead_nonce_size " >>"$AEAD_OUT_DIR/api.h"
    echo "#define CRYPTO_ABYTES $aead_tag_size " >>"$AEAD_OUT_DIR/api.h"
    echo "#define CRYPTO_NOOVERLAP 1 " >>"$AEAD_OUT_DIR/api.h"

    # Generate the encrypt.c wrapper to call through to the actual code.
    sed -e '1,$s/AEAD_ENCRYPT/'"$aead_encrypt"'/g' encrypt.c | \
      sed -e '1,$s/AEAD_DECRYPT/'"$aead_decrypt"'/g' | \
      sed -e '1,$s/HEADER/'"$aead_header"'/g' >"$AEAD_OUT_DIR/encrypt.c"

    # Generate KAT's for the algorithm.
    key_bits=`expr "${aead_key_size}" '*' 8`
    nonce_bits=`expr "${aead_nonce_size}" '*' 8`
    "$KAT_GEN" $aead_kat_options "$aead_meta_name" "$AEAD_OUT_DIR/../LWC_AEAD_KAT_${key_bits}_${nonce_bits}.txt"
done

# Generate the code for the hash algorithms.
for info_file in *hash ; do
    # Load the algorithm properties from the *.info file.
    unset hash_family
    unset hash_name
    unset hash_meta_name
    unset hash_srcdir
    unset hash_size
    unset hash_exclude
    unset hash_function
    unset hash_header
    unset hash_kat_options
    . ./$info_file
    echo $info_file

    # Create the directory structure for the algorithm.
    HASH_OUT_DIR="$OUT_DIR/$hash_family/Implementations/crypto_hash/$hash_name/$TAG"
    mkdir -p "$HASH_OUT_DIR"

    # Copy the source files that make up the algorithm.
    cp "$SRC_DIR/$hash_srcdir"/*.[ch] "$HASH_OUT_DIR"
    if test -n "$hash_exclude" ; then
        for exclude in $hash_exclude ; do
            rm -f "$HASH_OUT_DIR/$exclude"
        done
    fi

    # Generate the api.h file with the algorithm properties.
    echo "#define CRYPTO_BYTES $hash_size" >"$HASH_OUT_DIR/api.h"

    # Generate the hash wrapper to call through to the actual code.
    sed -e '1,$s/HASH_FUNCTION/'"$hash_function"'/g' hash.c | \
      sed -e '1,$s/HEADER/'"$hash_header"'/g' >"$HASH_OUT_DIR/hash.c"

    # Generate KAT's for the algorithm.
    hash_bits=`expr "${hash_size}" '*' 8`
    "$KAT_GEN" $hash_kat_options "$hash_meta_name" "$HASH_OUT_DIR/../LWC_HASH_KAT_${hash_bits}.txt"
done

exit 0
