#!/bin/bash
#
# DB_killer — Setup fast (tmpfs) and slow (ext4-on-tmpfs) directories
#
# Based on RQG's MK_EXT4_VAR.sh (GPL-2.0, MariaDB Corporation)
#
# Creates:
#   /dev/shm/db_killer       — fast dir (tmpfs, RAM-backed)
#   /dev/shm/db_killer_ext4  — slow dir (ext4 filesystem on a RAM-backed file)
#
# The slow dir is an ext4 filesystem created inside /dev/shm so it's fast
# but exercises different InnoDB code paths than tmpfs (e.g. O_DIRECT,
# fsync behavior, journal handling). This is the same approach RQG uses.
#
# Usage:
#   sudo bash setup_dirs.sh          # create with default 35% of /dev/shm
#   sudo bash setup_dirs.sh 50       # use 50% of /dev/shm for ext4
#   sudo bash setup_dirs.sh teardown # unmount and clean up
#
# After setup, run DB_killer with:
#   python3 main.py --basedir /path/to/build \
#       --fast-dir /dev/shm/db_killer \
#       --slow-dir /dev/shm/db_killer_ext4 \
#       --rounds 0 --rr
#

set -e

FAST_DIR="/dev/shm/db_killer"
SLOW_DIR="/dev/shm/db_killer_ext4"
CONTAINER="/dev/shm/db_killer_container"
PCT="${1:-35}"  # % of /dev/shm to use for ext4 container

# --- Teardown mode ---
if [ "$1" = "teardown" ]; then
    echo "Tearing down..."
    sudo umount "$SLOW_DIR" 2>/dev/null || true
    sudo rm -f "$CONTAINER"
    sudo rm -rf "$SLOW_DIR"
    rm -rf "$FAST_DIR"
    echo "Done. Cleaned up $FAST_DIR, $SLOW_DIR, $CONTAINER"
    exit 0
fi

# --- Must not run as root (RQG convention) ---
if [ "root" = "$USER" ]; then
    echo "ERROR: Don't run as root. Run as your normal user with sudo."
    echo "Usage: sudo -E bash setup_dirs.sh"
    exit 1
fi

# --- Check /dev/shm exists ---
if [ ! -d /dev/shm ]; then
    echo "ERROR: /dev/shm does not exist"
    exit 1
fi

# --- Create fast dir (simple tmpfs directory) ---
mkdir -p "$FAST_DIR"
echo "Fast dir: $FAST_DIR (tmpfs)"

# --- Create slow dir (ext4 filesystem on tmpfs-backed file) ---

# Unmount if already mounted
sudo umount "$SLOW_DIR" 2>/dev/null || true

# Create mount point
sudo mkdir -p "$SLOW_DIR"

# Calculate size: PCT% of available /dev/shm space
SPACE_AVAIL=$(df -k --output=avail /dev/shm | tail -1 | tr -d ' ')
SPACE_KB=$(( (SPACE_AVAIL * PCT) / 100 ))

# Cap at 200GB (no point using more)
MAX_KB=209715200
if [ "$SPACE_KB" -gt "$MAX_KB" ]; then
    SPACE_KB=$MAX_KB
fi

echo "Allocating ext4 container: ${SPACE_KB}K (${PCT}% of available /dev/shm)"

# Create the container file
sudo rm -f "$CONTAINER"
sudo fallocate -l "${SPACE_KB}K" "$CONTAINER"

# Format as ext4: no reserved blocks, no journal (faster)
sudo mkfs.ext4 -m0 -O ^has_journal -q "$CONTAINER"

# Mount
sudo mount "$CONTAINER" "$SLOW_DIR"
sudo chown "$USER" "$SLOW_DIR" "$CONTAINER"
sudo chmod 775 "$SLOW_DIR"

# Pre-allocate to full size (prevents /dev/shm space surprises later)
echo "Pre-allocating ext4 space (may take a moment)..."
DUMMY="$SLOW_DIR/.preallocate"
dd if=/dev/zero of="$DUMMY" bs=1M 2>/dev/null || true
rm -f "$DUMMY"

echo ""
echo "=== Setup complete ==="
echo "  Fast dir (tmpfs): $FAST_DIR"
echo "  Slow dir (ext4):  $SLOW_DIR"
echo ""
echo "Run DB_killer with:"
echo "  python3 main.py --basedir /path/to/mariadb-build \\"
echo "      --fast-dir $FAST_DIR \\"
echo "      --slow-dir $SLOW_DIR \\"
echo "      --rounds 0 --rr --multi-threaded --randomize-options"
echo ""
df -h "$FAST_DIR" "$SLOW_DIR"
