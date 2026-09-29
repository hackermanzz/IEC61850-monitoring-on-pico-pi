#!/bin/sh
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
prefix=${IEC61850_PREFIX:-/usr/local}
compiler=${CC:-cc}
output=${OUTPUT:-"$script_dir/iec61850_bus14"}

"$compiler" \
    -std=c11 \
    -O2 \
    -Wall \
    -Wextra \
    -Wpedantic \
    -Wstrict-prototypes \
    -Wmissing-prototypes \
    -pthread \
    -I"$prefix/include" \
    -I"$prefix/include/libiec61850" \
    "$script_dir/iec61850_bus14.c" \
    -L"$prefix/lib" \
    -liec61850 \
    -pthread \
    -o "$output"

printf 'Built %s\n' "$output"
