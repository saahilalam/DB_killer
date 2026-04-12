#!/bin/bash
#
# Simple crash testcase reducer for MariaDB AST Fuzzer.
# Inspired by pquery's reducer.sh — uses the actual mariadb client,
# searches error log for the crash signature, retries for sporadic bugs.
#
# Usage:
#   ./reduce.sh <basedir> <crash.sql> [crash.opt] [trials_per_attempt]
#
# Example:
#   ./reduce.sh /path/to/mariadb-build crashes/crash_0001.sql crashes/crash_0001.opt
#

set -u

BASEDIR="${1:?Usage: $0 <basedir> <crash.sql> [crash.opt] [trials]}"
INPUTFILE="${2:?Usage: $0 <basedir> <crash.sql> [crash.opt] [trials]}"
OPTFILE="${3:-}"
TRIALS="${4:-3}"   # Try each reduction attempt this many times (for sporadic crashes)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKDIR=$(mktemp -d /tmp/ast_reducer_XXXXXX)
RESULT_DIR="$(dirname "$INPUTFILE")"
BASENAME="$(basename "$INPUTFILE" .sql)"
OUTPUT="${RESULT_DIR}/${BASENAME}_reduced.sql"

# Find binaries
MYSQLD="$BASEDIR/bin/mariadbd"
[ ! -f "$MYSQLD" ] && MYSQLD="$BASEDIR/bin/mysqld"
MYSQL="$BASEDIR/bin/mariadb"
[ ! -f "$MYSQL" ] && MYSQL="$BASEDIR/bin/mysql"
INSTALL_DB="$BASEDIR/scripts/mariadb-install-db"
[ ! -f "$INSTALL_DB" ] && INSTALL_DB="$BASEDIR/scripts/mysql_install_db"
[ ! -f "$INSTALL_DB" ] && INSTALL_DB="$BASEDIR/bin/mariadb-install-db"

# Load mysqld options from .opt file
MYEXTRA="--no-defaults --skip-grant-tables --core-file --log-output=none"
MYEXTRA="$MYEXTRA --loose-innodb_fatal_semaphore_wait_threshold=300"
if [ -n "$OPTFILE" ] && [ -f "$OPTFILE" ]; then
    while IFS= read -r line; do
        [ -n "$line" ] && [[ ! "$line" =~ ^# ]] && MYEXTRA="$MYEXTRA $line"
    done < "$OPTFILE"
fi

# Extract bootstrap args (page_size)
BOOTSTRAP_ARGS=""
if echo "$MYEXTRA" | grep -q "innodb_page_size\|innodb-page-size"; then
    BOOTSTRAP_ARGS=$(echo "$MYEXTRA" | grep -oP '\-\-loose-innodb[_-]page[_-]size=\S+')
fi

# Get crash signature from existing error log (if available)
ERRLOG_ORIG="${RESULT_DIR}/${BASENAME}_vardir/error.log"
CRASH_TEXT=""
if [ -f "$ERRLOG_ORIG" ]; then
    # Look for assertion or signal
    CRASH_TEXT=$(grep -m1 "Assertion.*failed\|got signal" "$ERRLOG_ORIG" | head -1)
fi

if [ -z "$CRASH_TEXT" ]; then
    echo "No crash signature found. Will look for any crash (server exit != 0)."
    SEARCH_MODE="any_crash"
else
    # Extract just the assertion for matching
    ASSERT_TEXT=$(echo "$CRASH_TEXT" | grep -oP "Assertion.*failed" | head -1)
    if [ -n "$ASSERT_TEXT" ]; then
        SEARCH_MODE="assertion"
        echo "Crash signature: $ASSERT_TEXT"
    else
        SEARCH_MODE="any_crash"
        echo "Crash signature: $CRASH_TEXT"
    fi
fi

# Count input lines
TOTAL_LINES=$(grep -c ";" "$INPUTFILE" 2>/dev/null || wc -l < "$INPUTFILE")
echo "Input: $INPUTFILE ($TOTAL_LINES statements)"
echo "Build: $BASEDIR"
echo "Workdir: $WORKDIR"
echo "Trials per attempt: $TRIALS"
echo ""

# ─── Functions ───

init_datadir() {
    rm -rf "$WORKDIR/data"
    mkdir -p "$WORKDIR/data"
    $INSTALL_DB --basedir="$BASEDIR" --datadir="$WORKDIR/data" \
        --user="$USER" --auth-root-authentication-method=normal \
        $BOOTSTRAP_ARGS >/dev/null 2>&1
}

start_server() {
    $MYSQLD --basedir="$BASEDIR" --datadir="$WORKDIR/data" \
        --socket="$WORKDIR/sock" --port=0 --skip-networking \
        --pid-file="$WORKDIR/pid" --log-error="$WORKDIR/error.log" \
        --tmpdir="$WORKDIR" $MYEXTRA &
    SPID=$!

    # Wait for socket
    for i in $(seq 1 60); do
        [ -S "$WORKDIR/sock" ] && sleep 0.3 && return 0
        sleep 0.5
        # Check if process died
        kill -0 $SPID 2>/dev/null || return 1
    done
    return 1
}

stop_server() {
    if [ -f "$WORKDIR/pid" ]; then
        kill $(cat "$WORKDIR/pid") 2>/dev/null
        sleep 1
        kill -9 $(cat "$WORKDIR/pid") 2>/dev/null
    fi
    sleep 0.5
}

check_crash() {
    # Returns 0 if crash detected, 1 otherwise
    if [ ! -f "$WORKDIR/error.log" ]; then
        return 1
    fi

    if [ "$SEARCH_MODE" = "assertion" ]; then
        grep -q "$ASSERT_TEXT" "$WORKDIR/error.log" 2>/dev/null && return 0
    else
        # Any crash: look for signal or assertion
        grep -qE "got signal|Assertion.*failed" "$WORKDIR/error.log" 2>/dev/null && return 0
    fi
    return 1
}

test_sql() {
    # Run a SQL file and check if it crashes the server
    # Returns 0 if crash reproduced, 1 otherwise
    local sqlfile="$1"

    for trial in $(seq 1 $TRIALS); do
        init_datadir
        if ! start_server; then
            stop_server
            continue
        fi

        # Create test database and source the SQL using Python connector
        # (same as the fuzzer uses — CLI may handle queries differently)
        $MYSQL --socket="$WORKDIR/sock" -u root -e "CREATE DATABASE IF NOT EXISTS test" 2>/dev/null
        python3 "$SCRIPT_DIR/_replay.py" "$WORKDIR/sock" "$sqlfile" 2>/dev/null

        # Give it a moment for any async InnoDB operations
        sleep 1

        # Check if server crashed
        if check_crash; then
            stop_server
            return 0
        fi

        # Also check if server is still alive
        if [ -f "$WORKDIR/pid" ] && ! kill -0 $(cat "$WORKDIR/pid") 2>/dev/null; then
            if check_crash; then
                stop_server
                return 0
            fi
        fi

        stop_server
    done
    return 1
}

# ─── Main reduction ───

echo "=== Verifying crash reproduces ==="
if ! test_sql "$INPUTFILE"; then
    echo "ERROR: Cannot reproduce crash after $TRIALS trials."
    echo "Try increasing trials: $0 $BASEDIR $INPUTFILE $OPTFILE 10"
    rm -rf "$WORKDIR"
    exit 1
fi
echo "Crash confirmed!"
echo ""

# Copy input as working file
cp "$INPUTFILE" "$WORKDIR/current.sql"
CURRENT="$WORKDIR/current.sql"
CURRENT_LINES=$(grep -c ";" "$CURRENT")

echo "=== Stage 1: Chunk removal ==="
CHUNK=$((CURRENT_LINES / 2))
[ $CHUNK -lt 1 ] && CHUNK=1

while [ $CHUNK -ge 1 ]; do
    LINES=$(grep -c ";" "$CURRENT")
    echo "Chunk size: $CHUNK (file: $LINES statements)"

    OFFSET=0
    CHANGED=0

    while [ $OFFSET -lt $((LINES - 1)) ]; do
        END=$((OFFSET + CHUNK))
        [ $END -ge $LINES ] && END=$((LINES - 1))  # Never remove last line

        # Create candidate: remove lines OFFSET to END
        head -n $OFFSET "$CURRENT" > "$WORKDIR/candidate.sql"
        tail -n +$((END + 1)) "$CURRENT" >> "$WORKDIR/candidate.sql"

        CAND_LINES=$(wc -l < "$WORKDIR/candidate.sql")
        [ $CAND_LINES -lt 1 ] && { OFFSET=$((OFFSET + CHUNK)); continue; }

        if test_sql "$WORKDIR/candidate.sql"; then
            echo "  Removed lines $((OFFSET+1))-$END → still crashes ($CAND_LINES lines left)"
            cp "$WORKDIR/candidate.sql" "$CURRENT"
            LINES=$(grep -c ";" "$CURRENT")
            CHANGED=1
        else
            OFFSET=$((OFFSET + CHUNK))
        fi
    done

    if [ $CHANGED -eq 0 ] && [ $CHUNK -eq 1 ]; then
        break
    fi

    CHUNK=$((CHUNK / 2))
    [ $CHUNK -lt 1 ] && CHUNK=1
    [ $CHANGED -eq 0 ] && [ $CHUNK -eq 1 ] && break
done

echo ""
echo "=== Stage 2: Single line removal ==="
LINES=$(grep -c ";" "$CURRENT")
LINE=1
while [ $LINE -lt $LINES ]; do
    # Never remove the last line (crash query)
    [ $LINE -eq $LINES ] && break

    sed "${LINE}d" "$CURRENT" > "$WORKDIR/candidate.sql"

    if test_sql "$WORKDIR/candidate.sql"; then
        echo "  Removed line $LINE/$LINES → still crashes"
        cp "$WORKDIR/candidate.sql" "$CURRENT"
        LINES=$((LINES - 1))
        # Don't increment — try same position again
    else
        LINE=$((LINE + 1))
    fi
done

# ─── Done ───

FINAL_LINES=$(grep -c ";" "$CURRENT")
cp "$CURRENT" "$OUTPUT"

# Also copy the .opt file
if [ -n "$OPTFILE" ] && [ -f "$OPTFILE" ]; then
    cp "$OPTFILE" "${OUTPUT%.sql}.opt"
fi

echo ""
echo "============================================================"
echo " Reduction complete: $TOTAL_LINES → $FINAL_LINES statements"
echo " Reduced file: $OUTPUT"
if [ -n "$OPTFILE" ]; then
    echo " Options file: ${OUTPUT%.sql}.opt"
fi
echo ""
echo " To reproduce:"
echo "   $INSTALL_DB --basedir=$BASEDIR --datadir=/tmp/repro $BOOTSTRAP_ARGS"
echo "   $MYSQLD --basedir=$BASEDIR --datadir=/tmp/repro \\"
echo "       --skip-grant-tables --skip-networking --core-file $BOOTSTRAP_ARGS &"
echo "   sleep 3"
echo "   $MYSQL -u root test < $OUTPUT"
echo "============================================================"

# Cleanup
rm -rf "$WORKDIR"
