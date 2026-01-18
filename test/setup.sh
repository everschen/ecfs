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
    echo "[ECFS] build"
    cd "$ECFS_DIR"
    make -j6

    echo "[ECFS] insmod"
    sudo insmod ecfs.ko
    IMG=$TEST_PATH/test_ecfs.img
    sudo umount /mnt/ecfs 2>/dev/null || true
    E2FS_PATH="$TEST_PATH/e2fsprogs/misc/"
    MNT=/mnt/ecfs
    FSTYPE=ecfs
    MKE2FS="$ECFS_MKE2FS"
else
    sudo umount /mnt/ext4 2>/dev/null || true
    IMG=$TEST_PATH/test_ext4.img
    E2FS_PATH=""
    MNT=/mnt/ext4
    FSTYPE=ext4
    MKE2FS="mke2fs"
fi


# ---------- loop ----------
LOOP=$(sudo losetup -f --show "$IMG")
echo "[LOOP] $LOOP"

# ---------- 清历史痕迹 ----------
sudo wipefs -a "$LOOP"


echo "[MKFS] using $MKE2FS, inode_ratio=32768"

sudo "$MKE2FS" -F -t ext4 \
  -b 4096 \
  -I 256 \
  -i 32768 \
  -E lazy_itable_init=0,lazy_journal_init=0 \
  "$LOOP"



sudo mkdir -p "$MNT"
echo "[MOUNT] $FSTYPE on $MNT"
sudo mount -t "$FSTYPE" "$LOOP" "$MNT"

# ---------- 强校验 ----------
SRC=$(findmnt -n -o SOURCE --target "$MNT")
if [ "$SRC" != "$LOOP" ]; then
    echo "ERROR: mounted $SRC, expected $LOOP"
    exit 1
fi

cd $MNT
pwd
ls -lia
echo "cd $MNT"
