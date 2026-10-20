#!/bin/sh
# Replays lab captures through the analyzer on the host (gcc, no board).
#  1. legacy settings (4 GOOSE slots, 4 raw frames)  -> must match the old code
#  2. new settings (16 slots, metadata only)          -> more streams scored
#  3. one frame in 20 dropped: per stream gap policy vs old global reset
# Usage: sh tests/analyzer_compare/run.sh  (from the repository root)
set -e
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
A=$ROOT/rmii/examples/analyzer
G=$ROOT/firmware/generated_batch
OUT=${TMPDIR:-/tmp}/is18_analyzer_compare
mkdir -p "$OUT"
gcc -O2 -std=c99 -DNEW_API -DANALYZER_STORE_WINDOW_FRAMES=1 \
    -DANALYZER_MAXIMUM_GOOSE_STREAMS=4 -I"$A" -I"$G" \
    "$ROOT/tests/analyzer_compare/analyzer_compare.c" "$A/analyzer.c" \
    "$G/generated_batch_models.c" -lm -o "$OUT/legacy"
gcc -O2 -std=c99 -DNEW_API -I"$A" -I"$G" \
    "$ROOT/tests/analyzer_compare/analyzer_compare.c" "$A/analyzer.c" \
    "$G/generated_batch_models.c" -lm -o "$OUT/new"
for capture in "Test Dataset/test" "Training Dataset/tripspoof" "Training Dataset/svspoof"; do
    name=$(basename "$capture")
    python3 "$ROOT/tests/analyzer_compare/pcap2bin.py" "$ROOT/$capture.pcapng" "$OUT/$name.bin" > /dev/null
    echo "== $name"
    printf "legacy settings:    "; "$OUT/legacy" "$OUT/$name.bin" 2>&1 > /dev/null
    printf "new settings:       "; "$OUT/new" "$OUT/$name.bin" 2>&1 > /dev/null
    printf "legacy, 1/20 lost:  "; "$OUT/legacy" "$OUT/$name.bin" 20 2>&1 > /dev/null
    printf "new, 1/20 lost:     "; "$OUT/new" "$OUT/$name.bin" 20 2>&1 > /dev/null
done
