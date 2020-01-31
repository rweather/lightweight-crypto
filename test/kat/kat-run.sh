#!/bin/sh
# Usage: kat-run.sh [--no-generate] ./kat ./kat-gen ALG FILE [gen-options]

# Parse the command-line parameters.
GENERATE=1
if test "x$1" = "x--no-generate" ; then
    GENERATE=0
    shift
fi
KAT="$1"
KAT_GEN="$2"
ALG="$3"
FILE="$4"
shift
shift
shift
shift

# Run the standard KAT vectors.
if ! "$KAT" "$ALG" "$FILE" ; then
    exit 1
fi

# Generate the vectors ourselves and compare.
if test "$GENERATE" = 1 ; then
    if ! "$KAT_GEN" $* "$ALG" "$FILE".tmp; then
        rm -f "$FILE".tmp
        exit 1
    fi
    if diff --strip-trailing-cr -q "$FILE" "$FILE".tmp >/dev/null 2>/dev/null ; then
        rm -f "$FILE".tmp
    else
        echo "******* KAT vectors for $ALG were not generated correctly"
        echo "******* See ${FILE}.tmp for the generated output"
        exit 1
    fi
fi

# Done
exit 0
