#!/bin/bash
#
# DB_killer — One-shot crash reducer
#
# Auto-extracts the crash signature from .sig file and runs pquery's
# reducer_new_text_string_pquery.sh to produce a minimal reproducer.
#
# Usage:
#   bash reduce_crash.sh <build-dir> <crash-prefix> [extra-mysqld-opts]
#
# Example:
#   bash reduce_crash.sh /Server_bin/10.11_debug_Og ./crashes/crash_0001
#   bash reduce_crash.sh /Server_bin/10.11_debug_Og ./crashes/crash_0001 "--sql_mode= --innodb-page-size=64K"
#
# Before running, ensure:
#   - Your MariaDB build is at <build-dir>
#   - The reducer_new_text_string_pquery.sh script exists in <build-dir>
#     (it's copied there by mariadb-qa's setup)
#

set -e

BASEDIR="${1:?Usage: $0 <build-dir> <crash-prefix> [extra-mysqld-opts]}"
CRASH_PREFIX="${2:?Usage: $0 <build-dir> <crash-prefix> [extra-mysqld-opts]}"
EXTRA_OPTS="${3:---sql_mode=}"

# Strip .sql extension if user passed the full .sql filename
CRASH_PREFIX="${CRASH_PREFIX%.sql}"
# Strip trailing slash
CRASH_PREFIX="${CRASH_PREFIX%/}"

# Handle new layout: crashes/crash_0001/ (directory with files inside)
# User may pass:
#   crashes/crash_0001          — directory path (new layout)
#   crashes/crash_0001/crash_0001 — explicit prefix (new layout)
#   crashes/crash_0001          — legacy flat layout prefix
if [ -d "$CRASH_PREFIX" ] && [ -f "$CRASH_PREFIX/$(basename $CRASH_PREFIX).sql" ]; then
    # New layout: crashes/crash_0001/ → crashes/crash_0001/crash_0001
    CRASH_PREFIX="$CRASH_PREFIX/$(basename $CRASH_PREFIX)"
fi

SQL_FILE="${CRASH_PREFIX}.sql"
SIG_FILE="${CRASH_PREFIX}.sig"
OPT_FILE="${CRASH_PREFIX}.opt"

# --- Validate inputs ---

if [ ! -f "$SQL_FILE" ]; then
    echo "ERROR: SQL file not found: $SQL_FILE"
    exit 1
fi

if [ ! -f "$SIG_FILE" ]; then
    echo "ERROR: Signature file not found: $SIG_FILE"
    echo "Cannot auto-extract signature. Run the reducer manually instead."
    exit 1
fi

if [ ! -d "$BASEDIR" ]; then
    echo "ERROR: Build directory not found: $BASEDIR"
    exit 1
fi

# Find the reducer script
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REDUCER=""
for candidate in \
    "$BASEDIR/reducer_new_text_string_pquery.sh" \
    "$BASEDIR/reducer_new_text_string.sh" \
    "$SCRIPT_DIR/mariadb-qa/reducer_new_text_string_pquery.sh" \
    "$SCRIPT_DIR/mariadb-qa/reducer_new_text_string.sh" \
    "$SCRIPT_DIR/mariadb-qa/reducer.sh" \
    "$SCRIPT_DIR/../mariadb-qa/reducer.sh" \
    "$HOME/mariadb-qa/reducer.sh"; do
    if [ -x "$candidate" ]; then
        REDUCER="$candidate"
        break
    fi
done

if [ -z "$REDUCER" ]; then
    echo "ERROR: No reducer script found."
    echo "Looked in:"
    echo "  $BASEDIR/reducer_new_text_string_pquery.sh"
    echo "  $BASEDIR/reducer_new_text_string.sh"
    echo "  $SCRIPT_DIR/mariadb-qa/reducer*.sh"
    echo "  $HOME/mariadb-qa/reducer.sh"
    echo ""
    echo "Fix: run mariadb-qa's startup.sh in your build dir:"
    echo "  cd $BASEDIR && bash ~/mariadb-qa/startup.sh"
    echo "This copies the reducer scripts into the build dir."
    exit 1
fi

# --- Extract signature (first non-comment line of .sig) ---

SIGNATURE=$(grep -v '^#' "$SIG_FILE" | grep -v '^$' | head -1)

if [ -z "$SIGNATURE" ]; then
    echo "ERROR: No signature found in $SIG_FILE"
    exit 1
fi

# --- Append extra mysqld opts from .opt file (excluding noise) ---

if [ -f "$OPT_FILE" ]; then
    while IFS= read -r line; do
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [ -z "$line" ] && continue
        [[ "$line" =~ ^# ]] && continue

        # Skip options that aren't relevant for reduction
        [[ "$line" =~ innodb_fatal_semaphore ]] && continue
        [[ "$line" =~ idle_.*timeout ]] && continue
        [[ "$line" =~ connect_timeout ]] && continue
        [[ "$line" =~ max-connections ]] && continue
        [[ "$line" =~ max-statement-time ]] && continue
        [[ "$line" =~ debug_assert_on_not_freed ]] && continue
        [[ "$line" =~ log_output ]] && continue
        [[ "$line" =~ innodb-buffer-pool-size=128M ]] && continue

        EXTRA_OPTS="$EXTRA_OPTS $line"
    done < "$OPT_FILE"
fi

# --- Show what we're about to run ---

echo "============================================================"
echo " DB_killer → pquery reducer"
echo "============================================================"
echo " SQL file:   $SQL_FILE"
echo " Signature:  $SIGNATURE"
echo " Reducer:    $REDUCER"
echo " Build dir:  $BASEDIR"
echo " Extra opts: $EXTRA_OPTS"
echo "============================================================"
echo ""

# --- Run the reducer ---

cd "$BASEDIR"

SQL_FILE_ABS=$(readlink -f "$SQL_FILE")

"$REDUCER" "$SQL_FILE_ABS" "$SIGNATURE" "$EXTRA_OPTS"
