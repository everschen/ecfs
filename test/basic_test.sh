#!/bin/bash
set -e

MODE=${1:-ecfs}

IMG=/home/evers/test.img
inode_start_block=1059
ECFS_DIR=/home/evers/linux-6.17.0/fs/ecfs
ECFS_MKE2FS=/home/evers/e2fsprogs/misc/mke2fs

case "$MODE" in
    ecfs|ext4)
        ;;
    *)
        echo "Usage: $0 [ecfs|ext4]"
        exit 1
        ;;
esac

echo "===== FS TEST MODE: $MODE ====="

# ---------- 清理现场 ----------
sudo umount /mnt/ecfs 2>/dev/null || true
sudo umount /mnt/ext4 2>/dev/null || true

# ---------- ECFS：编译 & 加载 ----------
if [ "$MODE" = "ecfs" ]; then
    echo "[ECFS] build"
    cd "$ECFS_DIR"
    make -j6

    echo "[ECFS] insmod"
    sudo insmod ecfs.ko
fi

# ---------- loop ----------
LOOP=$(sudo losetup -f --show "$IMG")
echo "[LOOP] $LOOP"

# ---------- 清历史痕迹 ----------
sudo wipefs -a "$LOOP"

# ---------- mkfs ----------
if [ "$MODE" = "ecfs" ]; then
    MKE2FS="$ECFS_MKE2FS"
else
    MKE2FS="mke2fs"
fi

echo "[MKFS] using $MKE2FS, inode_ratio=32768"

sudo "$MKE2FS" -F -t ext4 \
  -b 4096 \
  -I 256 \
  -i 32768 \
  -E lazy_itable_init=0,lazy_journal_init=0 \
  "$LOOP"

# ---------- mount ----------
if [ "$MODE" = "ecfs" ]; then
    MNT=/mnt/ecfs
    FSTYPE=ecfs
else
    MNT=/mnt/ext4
    FSTYPE=ext4
fi

sudo mkdir -p "$MNT"
echo "[MOUNT] $FSTYPE on $MNT"
sudo mount -t "$FSTYPE" "$LOOP" "$MNT"

# ---------- 强校验 ----------
SRC=$(findmnt -n -o SOURCE --target "$MNT")
if [ "$SRC" != "$LOOP" ]; then
    echo "ERROR: mounted $SRC, expected $LOOP"
    exit 1
fi

# ---------- 测试 ----------
DIRNAME="di"
echo "[TEST] mkdir $DIRNAME"
sudo mkdir "$MNT/$DIRNAME"

echo "[TEST] touch file.txt"
sudo touch "$MNT/file.txt"

echo "[TEST] ls -lia $MNT"
ls -lia "$MNT"

echo "[TEST] write & read"
echo "Hello $MODE!" | sudo tee "$MNT/file.txt" >/dev/null
sudo cat "$MNT/file.txt"

echo "[TEST] ls -lia $MNT/$DIRNAME"
ls -lia "$MNT/$DIRNAME"

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
