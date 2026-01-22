#!/bin/bash
set -euo pipefail

EXT4_IMG=/home/evers/ext4.img
ECFS_IMG=/home/evers/ecfs.img
MNT_EXT4=/mnt/ext4_test
MNT_ECFS=/mnt/ecfs_test
SIZE=128M

ECFS_FSCK=fsck.ecfs

echo "== prepare images =="
truncate -s $SIZE $EXT4_IMG
truncate -s $SIZE $ECFS_IMG

LOOP_EXT4=$(sudo losetup -f --show $EXT4_IMG)
LOOP_ECFS=$(sudo losetup -f --show $ECFS_IMG)

echo "ext4 loop: $LOOP_EXT4"
echo "ecfs loop: $LOOP_ECFS"

echo "== mkfs =="
sudo mke2fs -t ext4 \
  -b 4096 \
  -I 256 \
  -i 32768 \
  -E lazy_itable_init=0,lazy_journal_init=0 \
  $LOOP_EXT4

sudo mkfs.ecfs $LOOP_ECFS

sudo mkdir -p $MNT_EXT4 $MNT_ECFS

echo "== mount =="
sudo mount -o errors=panic $LOOP_EXT4 $MNT_EXT4
sudo mount -t ecfs $LOOP_ECFS $MNT_ECFS

#####################################
# 对照操作开始
#####################################

run_ops() {
  local M=$1

  mkdir $M/dir1
  mkdir $M/dir1/sub

  touch $M/f1
  touch $M/f2

  rm $M/f1
  rmdir $M/dir1/sub
  rmdir $M/dir1

  mkdir $M/dirA
  mkdir $M/dirB
  rmdir $M/dirA

  mkdir $M/deep
  for i in $(seq 1 100); do
    mkdir $M/deep/d$i || break
  done
}

echo "== run ext4 ops =="
sudo bash -c "$(declare -f run_ops); run_ops $MNT_EXT4"

echo "== run ecfs ops =="
sudo bash -c "$(declare -f run_ops); run_ops $MNT_ECFS"

#####################################
# dump 状态（关键）
#####################################

echo "== ext4 tree =="
sudo ls -liaR $MNT_EXT4

echo "== ecfs tree =="
sudo ls -liaR $MNT_ECFS

sync

#####################################
# umount + fsck
#####################################

echo "== umount =="
sudo umount $MNT_EXT4
sudo umount $MNT_ECFS

echo "== fsck ext4 =="
sudo fsck.ext4 -fn $LOOP_EXT4 || true

echo "== fsck ecfs =="
sudo $ECFS_FSCK -fn $LOOP_ECFS || true

echo "== cleanup =="
sudo losetup -d $LOOP_EXT4
sudo losetup -d $LOOP_ECFS

echo "DONE"
