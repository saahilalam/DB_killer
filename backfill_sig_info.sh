#!/bin/bash
#
# Backfill existing crash .sig files with basedir/version/commit info.
#
# Usage:
#   bash backfill_sig_info.sh <crash-dir> <basedir>
#
# Example:
#   bash backfill_sig_info.sh crashes /Server_bin/10.11H_debug_Og
#

set -e

CRASH_DIR="${1:?Usage: $0 <crash-dir> <basedir>}"
BASEDIR="${2:?Usage: $0 <crash-dir> <basedir>}"

# Get version info (same for all crashes since same build)
MYSQLD="$BASEDIR/bin/mariadbd"
[ ! -x "$MYSQLD" ] && MYSQLD="$BASEDIR/bin/mysqld"

VERSION=""
if [ -x "$MYSQLD" ]; then
    VERSION=$("$MYSQLD" --version 2>/dev/null | head -1)
fi

COMMIT=""
BRANCH=""
if [ -d "$BASEDIR/.git" ]; then
    COMMIT=$(git -C "$BASEDIR" rev-parse HEAD 2>/dev/null)
    BRANCH=$(git -C "$BASEDIR" rev-parse --abbrev-ref HEAD 2>/dev/null)
fi

echo "Backfilling .sig files in $CRASH_DIR"
echo "  Basedir: $BASEDIR"
echo "  Version: ${VERSION:-unknown}"
echo "  Commit:  ${COMMIT:-unknown}"
echo "  Branch:  ${BRANCH:-unknown}"
echo ""

UPDATED=0
for sig in "$CRASH_DIR"/crash_*.sig "$CRASH_DIR"/crash_*/crash_*.sig; do
    [ -f "$sig" ] || continue

    # Skip if already has Basedir line
    if grep -q '^# Basedir:' "$sig"; then
        continue
    fi

    # Insert new header lines after the existing "# Tag:" line
    tmp=$(mktemp)
    awk -v basedir="$BASEDIR" -v version="$VERSION" -v commit="$COMMIT" -v branch="$BRANCH" '
        /^# Tag:/ {
            print
            print "# Basedir: " basedir
            if (version != "") print "# Version: " version
            if (commit != "")  print "# Commit: " commit
            if (branch != "")  print "# Branch: " branch
            next
        }
        { print }
    ' "$sig" > "$tmp"

    mv "$tmp" "$sig"
    UPDATED=$((UPDATED + 1))
    echo "Updated: $(basename $sig)"
done

echo ""
echo "Done. Updated $UPDATED .sig files."
