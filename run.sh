#!/bin/bash
#
# MariaDB AST Fuzzer — continuous run with rotating InnoDB configurations
#
# Usage:
#   ./run.sh /path/to/mariadb-build
#   ./run.sh /path/to/mariadb-build 500000    # queries per round
#   ./run.sh /path/to/mariadb-build 500000 5  # 5 rounds then stop
#
# Runs forever by default (--rounds 0). Each round picks different startup
# options. All crashes saved to ./crashes/ with full vardir + reproducer.
# Crash deduplication persists across all rounds.
# Ctrl+C to stop.
#

BASEDIR="${1:?Usage: $0 <basedir> [queries_per_round] [num_rounds]}"
QUERIES_PER_ROUND="${2:-500000}"
NUM_ROUNDS="${3:-0}"     # 0 = infinite
CRASH_DIR="./crashes"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ ! -f "$BASEDIR/bin/mariadbd" ] && [ ! -f "$BASEDIR/bin/mysqld" ]; then
    echo "ERROR: mariadbd not found in $BASEDIR/bin/"
    exit 1
fi

# All .zz gendata files
GENDATA_ARGS=""
for zz in "$SCRIPT_DIR"/grammars/zz/*.zz; do
    [ -f "$zz" ] && GENDATA_ARGS="$GENDATA_ARGS --gendata $zz"
done

# All grammar directories
GRAMMAR_ARGS=""
if [ -d "$SCRIPT_DIR/grammars" ]; then
    GRAMMAR_ARGS="--grammar $SCRIPT_DIR/grammars/"
fi

echo "============================================================"
echo " MariaDB AST Fuzzer — Continuous Run"
echo " Build:         $BASEDIR"
echo " Crashes:       $CRASH_DIR"
echo " Queries/round: $QUERIES_PER_ROUND"
echo " Rounds:        $([ "$NUM_ROUNDS" = "0" ] && echo "infinite" || echo "$NUM_ROUNDS")"
echo " Grammars:      $(ls "$SCRIPT_DIR"/grammars/*.yy 2>/dev/null | wc -l) base + $(ls "$SCRIPT_DIR"/grammars/modules/*.yy 2>/dev/null | wc -l) redefines"
echo " Ctrl+C to stop"
echo "============================================================"
echo ""

python3 "$SCRIPT_DIR/main.py" \
    --seed-dir "$SCRIPT_DIR/seeds/" \
    $GRAMMAR_ARGS \
    $GENDATA_ARGS \
    --runs 10 \
    --max-queries "$QUERIES_PER_ROUND" \
    --basedir "$BASEDIR" \
    --randomize-options \
    --rounds "$NUM_ROUNDS" \
    --round-delay 60 \
    --crash-dir "$CRASH_DIR"
