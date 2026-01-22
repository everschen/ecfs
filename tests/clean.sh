#!/bin/bash
set -e

MODE=${1:-ecfs}

TEST_PATH=$HOME

ECFS_DIR=$TEST_PATH/linux-6.17.0/fs/ecfs
ECFS_MKE2FS=$TEST_PATH/e2fsprogs/misc/mke2fs

inode_start_block=37

case "$MODE" in
    ecfs|ext4)
        ;;
    *)
        echo "Usage: $0 [ecfs|ext4]"
        exit 1
        ;;
esac

echo "===== FS TEST MODE: $MODE ====="

MKE2FS="mke2fs"


# ---------- ECFS：编译 & 加载 ----------
if [ "$MODE" = "ecfs" ]; then
    IMG=$TEST_PATH/test_ecfs.img
    E2FS_PATH="$TEST_PATH/e2fsprogs/misc/"
    MNT=/mnt/ecfs
    FSTYPE=ecfs
    MKE2FS="$ECFS_MKE2FS"
else
    IMG=$TEST_PATH/test_ext4.img
    E2FS_PATH=""
    MNT=/mnt/ext4
    FSTYPE=ext4
    MKE2FS="mke2fs"
fi



if mountpoint -q $MNT; then
    echo "$MNT already mounted"
else
    echo "$MNT not mounted, no need to clean."
    exit 0
fi


LOOP=$(findmnt -n -o SOURCE --target "$MNT")

echo $LOOP

# ---------- 卸载 ----------
echo "[UMOUNT]"
sudo umount "$MNT"
sudo losetup -d "$LOOP"

# ---------- ECFS 卸载 ----------
if [ "$MODE" = "ecfs" ]; then
    echo "[ECFS] rmmod"
    sudo rmmod ecfs
fi

echo "===== DONE: $MODE ====="
