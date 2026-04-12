#!/bin/bash
#
# Prepares a pquery reducer.sh run from an AST fuzzer crash.
#
# Usage:
#   ./prep_reducer.sh <basedir> <crash_prefix>
#
# Example:
#   ./prep_reducer.sh /Server_bin/10.11_debug_Og ./crashes/crash_0001
#
# Creates: <crash_prefix>_reducer.sh — a ready-to-run reducer config
#
# This script bridges the AST fuzzer's crash output into pquery's
# reducer.sh format.  It reads the crash's error log, extracts the
# assertion/signal, and configures MODE + TEXT appropriately.
#
# MODES used:
#   MODE=3 + TEXT="file.cc:1234"  — for assertion failures (most precise)
#   MODE=3 + USE_NEW_TEXT_STRING=1 — for signal crashes with backtrace
#   MODE=4                        — fallback (any crash)
#

BASEDIR="${1:?Usage: $0 <basedir> <crash_prefix>}"
CRASH_PREFIX="${2:?Usage: $0 <basedir> <crash_prefix>}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Auto-detect reducer.sh: look next to this script, then common locations
REDUCER_SH=""
for candidate in \
    "$SCRIPT_DIR/mariadb-qa/reducer.sh" \
    "$SCRIPT_DIR/../mariadb-qa/reducer.sh" \
    "$HOME/mariadb-qa/reducer.sh"; do
    if [ -f "$candidate" ]; then
        REDUCER_SH="$(readlink -f "$candidate")"
        break
    fi
done
if [ -z "$REDUCER_SH" ]; then
    echo "ERROR: reducer.sh not found. Searched:"
    echo "  $SCRIPT_DIR/mariadb-qa/reducer.sh"
    echo "  $SCRIPT_DIR/../mariadb-qa/reducer.sh"
    echo "  $HOME/mariadb-qa/reducer.sh"
    echo "Clone mariadb-qa: git clone https://github.com/Percona-QA/mariadb-qa.git"
    exit 1
fi

SQL_FILE="${CRASH_PREFIX}.sql"
OPT_FILE="${CRASH_PREFIX}.opt"
SIG_FILE="${CRASH_PREFIX}.sig"
ERRLOG="${CRASH_PREFIX}_vardir/error.log"

if [ ! -f "$SQL_FILE" ]; then
    echo "ERROR: SQL file not found: $SQL_FILE"
    exit 1
fi

# ─── Extract crash signature from error log ───

CRASH_TEXT=""
ASSERT_TEXT=""
ASSERT_LOC=""
SIGNAL_TEXT=""

if [ -f "$ERRLOG" ]; then
    # Look for assertion: "mariadbd: /path/file.cc:1234: func(): Assertion `xxx' failed."
    ASSERT_TEXT=$(grep -m1 "Assertion.*failed" "$ERRLOG" | grep -oP "Assertion \`[^']+' failed" | head -1)

    # Extract file.cc:1234 for precise TEXT matching
    ASSERT_LOC=$(grep -m1 "Assertion.*failed" "$ERRLOG" | grep -oP '/\w+\.cc:\d+' | head -1 | sed 's|^/||')

    # Also check for InnoDB assertion: "Failing assertion: xxx"
    if [ -z "$ASSERT_TEXT" ]; then
        ASSERT_TEXT=$(grep -m1 "Failing assertion:" "$ERRLOG" | grep -oP "Failing assertion:\s*\K.*" | head -1)
        if [ -n "$ASSERT_TEXT" ]; then
            ASSERT_LOC=$(grep -B1 "Failing assertion:" "$ERRLOG" | grep -oP '/\w+\.cc:\d+' | head -1 | sed 's|^/||')
        fi
    fi

    # Look for signal
    SIGNAL_TEXT=$(grep -m1 "got signal" "$ERRLOG" | head -1)
fi

# Also try .sig file (our own signature format)
SIG_FROM_FILE=""
if [ -f "$SIG_FILE" ]; then
    SIG_FROM_FILE=$(grep -v "^#" "$SIG_FILE" | head -1)
fi

# ─── Determine MODE and TEXT ───

MODE=4
TEXT=""
USE_NEW_TEXT=0

if [ -n "$ASSERT_LOC" ]; then
    # Best case: we have file.cc:1234 from the assertion
    MODE=3
    TEXT="$ASSERT_LOC"
    echo "Strategy: MODE=3 with assertion location"
    echo "  Assertion: $ASSERT_TEXT"
    echo "  TEXT:       $TEXT"
elif [ -n "$ASSERT_TEXT" ]; then
    # Have assertion text but no file location — use the assertion itself
    MODE=3
    # Escape regex special chars for grep -E
    TEXT=$(echo "$ASSERT_TEXT" | sed 's/[[\.*^$()+?{|]/\\&/g')
    echo "Strategy: MODE=3 with assertion text"
    echo "  TEXT: $TEXT"
elif [ -n "$SIG_FROM_FILE" ] && echo "$SIG_FROM_FILE" | grep -q "|"; then
    # Have a pquery-style signature with | separators
    # Use new_text_string.sh matching via the top frame
    MODE=3
    USE_NEW_TEXT=1
    # Extract first meaningful part (skip assertion, use signal+frame)
    TEXT=$(echo "$SIG_FROM_FILE" | cut -d'|' -f1-2)
    echo "Strategy: MODE=3 with USE_NEW_TEXT_STRING + signature"
    echo "  Signature: $SIG_FROM_FILE"
    echo "  TEXT:       $TEXT"
elif [ -n "$SIGNAL_TEXT" ]; then
    # Have a signal but no assertion — use any crash mode
    MODE=4
    echo "Strategy: MODE=4 (any crash — signal but no assertion)"
    echo "  Signal: $SIGNAL_TEXT"
else
    MODE=4
    echo "Strategy: MODE=4 (any crash — no signature found)"
fi

# ─── Build MYEXTRA and MYINIT from .opt file ───
# MYINIT = options needed at datadir init time (innodb_page_size)
# MYEXTRA = options for server startup
# pquery reducer.sh expects these separated correctly

MYEXTRA="--no-defaults --log-output=none --skip-grant-tables"
MYINIT=""

if [ -f "$OPT_FILE" ]; then
    while IFS= read -r line; do
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [ -z "$line" ] && continue
        [[ "$line" =~ ^# ]] && continue

        # Only skip options that purely affect performance/logging,
        # never InnoDB behavior.  Previous list was too aggressive
        # and dropped options needed to reproduce crashes (e.g.
        # innodb_evict_tables, innodb-flush-log-at-trx-commit, log-bin).
        [[ "$line" =~ innodb_fatal_semaphore ]] && continue
        [[ "$line" =~ idle_.*timeout ]] && continue
        [[ "$line" =~ connect_timeout ]] && continue
        [[ "$line" =~ max-connections ]] && continue
        [[ "$line" =~ max-statement-time ]] && continue
        [[ "$line" =~ debug_assert_on_not_freed ]] && continue
        [[ "$line" =~ log_output ]] && continue
        # Skip the SMALLER buffer pool (128M) — keep the larger one
        [[ "$line" =~ innodb-buffer-pool-size=128M ]] && continue

        # innodb_page_size must go in MYINIT (needed at datadir init)
        if [[ "$line" =~ innodb_page_size|innodb-page-size ]]; then
            MYINIT="$MYINIT $line"
        fi
        MYEXTRA="$MYEXTRA $line"
    done < "$OPT_FILE"
fi

# ─── Get absolute paths ───

SQL_FILE_ABS=$(readlink -f "$SQL_FILE")
BASEDIR_ABS=$(readlink -f "$BASEDIR")

# ─── Auto-detect pquery and known_bugs ───

PQUERY_LOC=""
for candidate in \
    "$SCRIPT_DIR/pquery/pquery2-md" \
    "$SCRIPT_DIR/../mariadb-qa/pquery/pquery2-md" \
    "$(dirname "$REDUCER_SH")/pquery/pquery2-md" \
    "$HOME/mariadb-qa/pquery/pquery2-md"; do
    if [ -x "$candidate" ]; then
        PQUERY_LOC="$(readlink -f "$candidate")"
        break
    fi
done
[ -z "$PQUERY_LOC" ] && PQUERY_LOC="pquery2-md"  # fallback: hope it's in PATH

KNOWN_BUGS_LOC=""
for candidate in \
    "$SCRIPT_DIR/known_bugs.strings" \
    "$(dirname "$SQL_FILE_ABS")/known_bugs.strings" \
    "$(dirname "$SQL_FILE_ABS")/../known_bugs.strings"; do
    if [ -f "$candidate" ]; then
        KNOWN_BUGS_LOC="$(readlink -f "$candidate")"
        break
    fi
done

# ─── Create the reducer wrapper script ───

OUTPUT="${CRASH_PREFIX}_reducer.sh"

{
    echo '#!/bin/bash'
    echo "# Auto-generated reducer config for: $(basename $CRASH_PREFIX)"
    echo "# Generated by AST fuzzer prep_reducer.sh — $(date '+%Y-%m-%d %H:%M:%S')"
    echo "# Crash signature: ${SIG_FROM_FILE:-unknown}"
    echo ""
    echo "REDUCER=\"$REDUCER_SH\""
    echo ""
    echo "TMPRED=\$(mktemp /tmp/reducer_XXXXXX.sh)"
    echo "cp \"\$REDUCER\" \"\$TMPRED\""
    echo ""
    echo "# Inject settings into reducer.sh copy"
    echo "sed -i 's|^INPUTFILE=.*|INPUTFILE=$SQL_FILE_ABS|' \"\$TMPRED\""
    echo "sed -i 's|^MODE=.*|MODE=$MODE|' \"\$TMPRED\""
    echo "sed -i \"s#^TEXT=.*#TEXT=\\\"$TEXT\\\"#\" \"\$TMPRED\""
    echo "sed -i 's|^BASEDIR=.*|BASEDIR=\"$BASEDIR_ABS\"|' \"\$TMPRED\""
    echo "sed -i 's|^MYEXTRA=.*|MYEXTRA=\"$MYEXTRA\"|' \"\$TMPRED\""
    echo "sed -i 's|^MYINIT=.*|MYINIT=\"$MYINIT\"|' \"\$TMPRED\""
    echo "sed -i 's|^USE_NEW_TEXT_STRING=.*|USE_NEW_TEXT_STRING=$USE_NEW_TEXT|' \"\$TMPRED\""
    echo "sed -i 's|^USE_PQUERY=.*|USE_PQUERY=1|' \"\$TMPRED\""
    echo "sed -i 's|^PQUERY_LOC=.*|PQUERY_LOC=\"$PQUERY_LOC\"|' \"\$TMPRED\""
    echo "sed -i 's|^FORCE_SPORADIC=.*|FORCE_SPORADIC=1|' \"\$TMPRED\""
    echo "sed -i 's|^NR_OF_TRIAL_REPEATS=.*|NR_OF_TRIAL_REPEATS=20|' \"\$TMPRED\""
    echo "sed -i 's|^SCAN_FOR_NEW_BUGS=.*|SCAN_FOR_NEW_BUGS=0|' \"\$TMPRED\""
    if [ -n "$KNOWN_BUGS_LOC" ]; then
        echo "sed -i 's|^KNOWN_BUGS_LOC=.*|KNOWN_BUGS_LOC=\"$KNOWN_BUGS_LOC\"|' \"\$TMPRED\""
    fi
    echo ""
    echo "echo '============================================================'"
    echo "echo ' AST Fuzzer -> pquery reducer'"
    echo "echo ' SQL:      $SQL_FILE_ABS'"
    echo "echo ' Build:    $BASEDIR_ABS'"
    echo "echo ' Mode:     $MODE'"
    echo "echo ' Text:     $TEXT'"
    echo "echo ' Sporadic: yes (20 trials per attempt)'"
    echo "echo '============================================================'"
    echo "echo ''"
    echo ""
    echo "bash \"\$TMPRED\""
    echo "rm -f \"\$TMPRED\""
} > "$OUTPUT"

chmod +x "$OUTPUT"

echo ""
echo "============================================================"
echo " Reducer script created: $OUTPUT"
echo ""
echo " To reduce with pquery's reducer.sh:"
echo "   $OUTPUT"
echo ""
echo " To reduce with AST fuzzer's built-in reducer:"
echo "   python3 $(dirname "$0")/reducer.py \\"
echo "       --basedir $BASEDIR_ABS \\"
echo "       --input $SQL_FILE_ABS \\"
echo "       --opt $(readlink -f "${OPT_FILE}" 2>/dev/null || echo "${OPT_FILE}") \\"
echo "       --trials 5"
echo ""
echo " Settings:"
echo "   MODE=$MODE"
echo "   TEXT=\"$TEXT\""
echo "   MYEXTRA=\"$MYEXTRA\""
echo "   MYINIT=\"$MYINIT\""
echo "============================================================"
