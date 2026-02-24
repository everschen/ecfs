#!/bin/bash
set -e

MODE=${1:-ecfs}

TEST_PATH=$HOME

#IMG=$TEST_PATH/test.img
#inode_start_block=1059

inode_start_block=37




ECFS_DIR=$TEST_PATH/linux-6.17.0/fs/ecfs
ECFS_MKE2FS=$TEST_PATH/e2fsprogs/misc/mke2fs

sudo rm -f /tmp/fs_debug.log
sudo dmesg -C

case "$MODE" in
    ecfs|ext4)
        ;;
    *)
        echo "Usage: $0 [ecfs|ext4]"
        exit 1
        ;;
esac

echo "===== FS TEST MODE: $MODE ====="


if [ "$MODE" == "ecfs" ]; then
    ECFS_DIR=$TEST_PATH/linux-6.17.0/fs/ecfs
    E2FSPROGS=$TEST_PATH/e2fsprogs/
    MKE2FS=$E2FSPROGS/misc/mke2fs
    E2FS_PATH=$E2FSPROGS/misc/
    IMG=$TEST_PATH/test_ecfs.img
    MNT=/mnt/$MODE
    FSTYPE=$MODE
    MNT=/mnt/ecfs_test
    FSCK="$E2FSPROGS/e2fsck/e2fsck"
    echo "[ECFS] build"
    cd "$ECFS_DIR"
    make -j6
elif [ "$MODE" == "ext4" ]; then
    E2FSPROGS=$TEST_PATH/e2fsprogs_ori/
    MKE2FS=$E2FSPROGS/misc/mke2fs
    E2FS_PATH=$E2FSPROGS/misc/
    MNT=/mnt/$MODE
    FSTYPE=$MODE
    IMG=$TEST_PATH/test_ext4.img
    FSCK="$E2FSPROGS/e2fsck/e2fsck"
else
    echo "Usage: $0 [ecfs|ext4]   (default: ecfs)"
    exit 1
fi

sudo umount $MNT 2>/dev/null || true

#pass these info for inode, vb use later.
cat > /tmp/vars.sh <<EOF
export IMG=$IMG
export inode_start_block=$inode_start_block
export E2FSPROGS=$E2FSPROGS
EOF

sudo umount $MNT 2>/dev/null || true

if [ "$MODE" == "ecfs" ]; then
  if ! grep -q '^ecfs ' /proc/modules; then
      echo "[ECFS] insmod"
      sudo insmod ecfs.ko
  elif lsmod | awk '$1=="ecfs" && $3==0 {found=1} END{exit !found}'; then
      echo "ecfs loaded and refcnt = 0"
      sudo rmmod ecfs
      sudo insmod ecfs.ko
  else
      echo "ecfs loaded but refcnt != 0"
      exit 1
  fi
fi

cd $E2FSPROGS
make -j6

# ---------- loop ----------
LOOP=$(sudo losetup -f --show "$IMG")
echo "[LOOP] $LOOP"

# ---------- 清历史痕迹 ----------
sudo wipefs -a "$LOOP"

# ---------- mkfs ----------

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

echo "[TEST] write & read $MNT/$DIRNAME"
echo "Hello $MODE!" | sudo tee "$MNT/$DIRNAME/file2.txt" >/dev/null
sudo cat "$MNT/$DIRNAME/file2.txt"

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
