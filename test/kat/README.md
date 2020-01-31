
Running Known Answer Tests
==========================

This directory contains Known Answer Tests (KAT's) for the various
submissions to the NIST Lightweight Cryptography Competition.

The test vectors came from the NIST submissions and are Copyright their
original authors where applicable.

The "kat" tool can be run manually to execute a single algorithm's tests:

    ./kat GIMLI-24 GIMLI-24-CIPHER.txt

The arguments are the algorithm name and the file containing the KAT vectors.

Generating Known Answer Tests
=============================

This directory also contains a "kat-gen" tool for generating new KAT
vectors for the algorithms in the library.  For example:

    ./kat-gen GIMLI-24 GIMLI-24-CIPHER-new.txt

This should generate the same set of KAT vectors as in GIMLI-24-CIPHER.txt.
If the GIMLI-24-CIPHER.txt and GIMLI-24-CIPHER-new.txt files differ, then
there is probably something wrong with the algorithm implementation
in the library.

The following command-line options may be supplied to the "kat-gen" tool
prior to the algorithm name argument:

    --min-ad=SIZE
        Set the minimum associated data size, default is 0.

    --max-ad=SIZE
        Set the maximum associated data size, default is 32.

    --min-pt=SIZE
        Set the minimum plaintext message size, default is 0.

    --max-pt=SIZE
        Set the maximum plaintext message size, default is 32.

    --min-msg=SIZE
        Set the minimum message size for hash inputs, default is 0.

    --max-msg=SIZE
        Set the maximum message size for hash inputs, default is 1024.

    --random
    --random=SEED
        Randomize the key, nonce, plaintext, and hash input for each
        KAT vector based on the given SEED.  The same random data will
        be generated each time for a given SEED to allow reproducibility.
        If the SEED is omitted, then a seed based on the current system
        time will be generated and written to stdout.

The PRNG for "--random" is GIMLI-24-HASH in XOF mode, initialized by
absorbing the seed into the Gimli state, followed by squeezing out
random data as required to generate the KAT vectors.

Examples:

    ./kat-gen GIMLI-24 GIMLI-24-CIPHER-new.txt
    ./kat-gen --random ASCON-128 ASCON-128-new.txt
    ./kat-gen --random=FixedSeed --max-msg=15 --max-ad=0 \
        SATURNIN-Short SATURNIN-Short-new.txt

Adding New Algorithms
=====================

If you add a new algorithm to the library, then edit "algorithms.c" and add
the algorithm's meta-information block to the "ciphers" or "hashes" table.
