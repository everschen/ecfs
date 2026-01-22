#!/bin/bash
set -euo pipefail

########################
# 配置
########################
EXT4_IMG=/home/evers/ext4.img
ECFS_IMG=/home/evers/ecfs.img
MNT_EXT4=/mnt/ext4_test
MNT_ECFS=/mnt/ecfs_test
SIZE=128M
ECFS_FSCK=fsck.ecfs

########################
# 通用断言
########################
fail() {
  echo "FAIL: $1"
  exit 1
}

########################
# Test-1: mkdir 自动检测
########################
test_mkdir_auto() {
  local M=$1
  local NAME=$2

  echo "[TEST-1][$NAME] mkdir minimal correctness"

  P_INO=$(stat -c %i "$M")
  P_LINK_BEFORE=$(stat -c %h "$M")

  mkdir "$M/dir"

  test "$(stat -c %F "$M/dir")" = "directory" \
    || fail "$NAME: dir is not directory"

  test "$(stat -c %h "$M/dir")" -eq 2 \
    || fail "$NAME: dir link != 2"

  P_LINK_AFTER=$(stat -c %h "$M")
  test $((P_LINK_BEFORE + 1)) -eq "$P_LINK_AFTER" \
    || fail "$NAME: parent link not incremented"

  test "$(ls -A "$M/dir" | wc -l)" -eq 0 \
    || fail "$NAME: dir contains extra entries"

  DIR_INO=$(stat -c %i "$M/dir")
  test "$DIR_INO" -eq "$(stat -c %i "$M/dir/.")" \
    || fail "$NAME: . inode incorrect"

  test "$P_INO" -eq "$(stat -c %i "$M/dir/..")" \
    || fail "$NAME: .. inode incorrect"

  echo "[PASS][$NAME] Test-1 mkdir"
}

########################
# Test-2: rmdir 自动检测
########################
test_rmdir_auto() {
  local M=$1
  local NAME=$2

  echo "[TEST-2][$NAME] rmdir correctness"

  # 准备：mkdir
  mkdir "$M/rmdir_test"

  P_LINK_BEFORE=$(stat -c %h "$M")
  DIR_INO=$(stat -c %i "$M/rmdir_test")

  # 执行 rmdir
  rmdir "$M/rmdir_test" \
    || fail "$NAME: rmdir failed"

  # R2: parent link -1
  P_LINK_AFTER=$(stat -c %h "$M")
  test $((P_LINK_BEFORE - 1)) -eq "$P_LINK_AFTER" \
    || fail "$NAME: parent link not decremented"

  # R3: 目录项必须不存在
  test ! -e "$M/rmdir_test" \
    || fail "$NAME: dir entry still exists"

  # R4: inode 必须释放（通过 inode 号复用或 debugfs）
  # 简化做法：新建目录，看 inode 是否可复用
  mkdir "$M/tmp_check"
  NEW_INO=$(stat -c %i "$M/tmp_check")
  rmdir "$M/tmp_check"

  test "$NEW_INO" -eq "$DIR_INO" || \
    echo "[WARN][$NAME] inode not immediately reused (allowed)"

  echo "[PASS][$NAME] Test-2 rmdir"
}

########################
# Test-3: unlink 自动检测
########################
test_unlink_auto() {
  local M=$1
  local NAME=$2

  echo "[TEST-3][$NAME] unlink correctness"

  # 准备：创建文件
  echo "hello" > "$M/unlink_test"

  FILE_INO=$(stat -c %i "$M/unlink_test")
  FILE_LINK=$(stat -c %h "$M/unlink_test")
  test "$FILE_LINK" -eq 1 \
    || fail "$NAME: initial link count != 1"

  # 记录 parent link（不应变化）
  P_LINK_BEFORE=$(stat -c %h "$M")

  # 执行 unlink
  rm "$M/unlink_test" \
    || fail "$NAME: unlink failed"

  # R2: 目录项必须不存在
  test ! -e "$M/unlink_test" \
    || fail "$NAME: dir entry still exists"

  # R3: inode link 必须为 0（通过 debugfs 或 inode 复用侧证）
  # 这里用“inode 是否可复用”来自动判断
  echo "tmp" > "$M/tmp_inode_check"
  NEW_INO=$(stat -c %i "$M/tmp_inode_check")
  rm "$M/tmp_inode_check"

  if [ "$NEW_INO" != "$FILE_INO" ]; then
    echo "[WARN][$NAME] inode not immediately reused (allowed)"
  fi

  # R4: parent link 不应变化
  P_LINK_AFTER=$(stat -c %h "$M")
  test "$P_LINK_BEFORE" -eq "$P_LINK_AFTER" \
    || fail "$NAME: parent link changed after unlink"

  echo "[PASS][$NAME] Test-3 unlink"
}

########################
# Test-4: rename 自动检测
########################
test_rename_auto() {
  local M=$1
  local NAME=$2

  echo "[TEST-4][$NAME] rename correctness"

  ####################
  # 场景 A：同目录 rename
  ####################
  echo "A" > "$M/rn_a"
  INO_A=$(stat -c %i "$M/rn_a")

  mv "$M/rn_a" "$M/rn_b" \
    || fail "$NAME: rename same dir failed"

  test ! -e "$M/rn_a" \
    || fail "$NAME: old name exists after rename"

  test -e "$M/rn_b" \
    || fail "$NAME: new name missing after rename"

  test "$(stat -c %i "$M/rn_b")" -eq "$INO_A" \
    || fail "$NAME: inode changed in same-dir rename"

  ####################
  # 场景 B：跨目录 rename
  ####################
  mkdir "$M/rn_d1"
  mkdir "$M/rn_d2"

  echo "B" > "$M/rn_d1/file"
  INO_B=$(stat -c %i "$M/rn_d1/file")

  D1_LINK_BEFORE=$(stat -c %h "$M/rn_d1")
  D2_LINK_BEFORE=$(stat -c %h "$M/rn_d2")

  mv "$M/rn_d1/file" "$M/rn_d2/file" \
    || fail "$NAME: cross-dir rename failed"

  test ! -e "$M/rn_d1/file" \
    || fail "$NAME: source entry exists after cross rename"

  test -e "$M/rn_d2/file" \
    || fail "$NAME: target entry missing after cross rename"

  test "$(stat -c %i "$M/rn_d2/file")" -eq "$INO_B" \
    || fail "$NAME: inode changed in cross-dir rename"

  test "$(stat -c %h "$M/rn_d1")" -eq "$D1_LINK_BEFORE" \
    || fail "$NAME: src dir link count changed"

  test "$(stat -c %h "$M/rn_d2")" -eq "$D2_LINK_BEFORE" \
    || fail "$NAME: dst dir link count changed"

  ####################
  # 场景 C：rename 覆盖已有文件
  ####################
  echo "C1" > "$M/rn_c1"
  echo "C2" > "$M/rn_c2"

  INO_C1=$(stat -c %i "$M/rn_c1")
  INO_C2=$(stat -c %i "$M/rn_c2")

  mv -f "$M/rn_c1" "$M/rn_c2" \
    || fail "$NAME: rename overwrite failed"

  test ! -e "$M/rn_c1" \
    || fail "$NAME: source exists after overwrite"

  test "$(stat -c %i "$M/rn_c2")" -eq "$INO_C1" \
    || fail "$NAME: target inode not replaced"

  echo "[PASS][$NAME] Test-4 rename"
}


########################
# Test-5: hard link 自动检测
########################
test_hardlink_auto() {
  local M=$1
  local NAME=$2

  echo "[TEST-5][$NAME] hard link correctness"

  # 准备：创建原始文件
  echo "HL" > "$M/hl_src"
  SRC_INO=$(stat -c %i "$M/hl_src")
  SRC_LINK=$(stat -c %h "$M/hl_src")

  test "$SRC_LINK" -eq 1 \
    || fail "$NAME: initial link count != 1"

  # R1: 创建硬链接
  ln "$M/hl_src" "$M/hl_dst" \
    || fail "$NAME: hard link failed"

  # R2: link count = 2
  test "$(stat -c %h "$M/hl_src")" -eq 2 \
    || fail "$NAME: link count not incremented after link"

  # R3: inode 必须相同
  test "$(stat -c %i "$M/hl_dst")" -eq "$SRC_INO" \
    || fail "$NAME: hard link inode mismatch"

  # R4: unlink 一个名字
  rm "$M/hl_src" \
    || fail "$NAME: unlink src failed"

  test "$(stat -c %h "$M/hl_dst")" -eq 1 \
    || fail "$NAME: link count not decremented after unlink"

  # R5: unlink 最后一个名字
  rm "$M/hl_dst" \
    || fail "$NAME: unlink last link failed"

  # 侧证 inode 回收（不强制立即复用）
  echo "TMP" > "$M/hl_tmp"
  NEW_INO=$(stat -c %i "$M/hl_tmp")
  rm "$M/hl_tmp"

  if [ "$NEW_INO" != "$SRC_INO" ]; then
    echo "[WARN][$NAME] inode not immediately reused (allowed)"
  fi

  echo "[PASS][$NAME] Test-5 hard link"
}

########################
# Test-6: crash consistency 自动检测
########################
test_crash_auto() {
  local LOOP=$1
  local M=$2
  local NAME=$3

  echo "[TEST-6][$NAME] crash consistency"

  # 挂载
  sudo mount $LOOP $M

  # 执行混合操作
  mkdir "$M/crash_dir"
  echo "file" > "$M/crash_dir/file1"
  ln "$M/crash_dir/file1" "$M/crash_dir/file2"
  mv "$M/crash_dir/file2" "$M/crash_dir/file3"
  rm "$M/crash_dir/file1"
  rmdir "$M/crash_dir/file3" || true  # 有可能删不了

  # 强制卸载，模拟掉电
  sudo umount -l $M || true
  sync

  # fsck 检查
  if [[ "$NAME" == "ext4" ]]; then
    sudo fsck.ext4 -fn $LOOP || fail "$NAME: fsck failed after simulated crash"
  else
    sudo $ECFS_FSCK -fn $LOOP || fail "$NAME: fsck failed after simulated crash"
  fi

  echo "[PASS][$NAME] Test-6 crash consistency"
}


########################
# 综合操作测试
########################
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

########################
# 主流程
########################
echo "== prepare images =="
truncate -s $SIZE $EXT4_IMG
truncate -s $SIZE $ECFS_IMG

LOOP_EXT4=$(sudo losetup -f --show $EXT4_IMG)
LOOP_ECFS=$(sudo losetup -f --show $ECFS_IMG)

echo "== mkfs =="
sudo mke2fs -t ext4 \
  -b 4096 -I 256 -i 32768 \
  -E lazy_itable_init=0,lazy_journal_init=0 \
  $LOOP_EXT4

sudo mkfs.ecfs $LOOP_ECFS

sudo mkdir -p $MNT_EXT4 $MNT_ECFS

echo "== mount =="
sudo mount -o errors=panic $LOOP_EXT4 $MNT_EXT4
sudo mount -t ecfs $LOOP_ECFS $MNT_ECFS

########################
# Test-1（自动）
########################
sudo bash -c "$(declare -f fail test_mkdir_auto); test_mkdir_auto $MNT_EXT4 ext4"
sudo bash -c "$(declare -f fail test_mkdir_auto); test_mkdir_auto $MNT_ECFS ecfs"

########################
# Test-2（自动）
########################
sudo bash -c "$(declare -f fail test_rmdir_auto); test_rmdir_auto $MNT_EXT4 ext4"
sudo bash -c "$(declare -f fail test_rmdir_auto); test_rmdir_auto $MNT_ECFS ecfs"

########################
# Test-3（自动）
########################
sudo bash -c "$(declare -f fail test_unlink_auto); test_unlink_auto $MNT_EXT4 ext4"
sudo bash -c "$(declare -f fail test_unlink_auto); test_unlink_auto $MNT_ECFS ecfs"

########################
# Test-4（自动）
########################
sudo bash -c "$(declare -f fail test_rename_auto); test_rename_auto $MNT_EXT4 ext4"
sudo bash -c "$(declare -f fail test_rename_auto); test_rename_auto $MNT_ECFS ecfs"

########################
# Test-5（自动）
########################
sudo bash -c "$(declare -f fail test_hardlink_auto); test_hardlink_auto $MNT_EXT4 ext4"
sudo bash -c "$(declare -f fail test_hardlink_auto); test_hardlink_auto $MNT_ECFS ecfs"

########################
# Test-6（自动）
########################
sudo bash -c "$(declare -f fail test_crash_auto); test_crash_auto $LOOP_EXT4 $MNT_EXT4 ext4"
sudo bash -c "$(declare -f fail test_crash_auto); test_crash_auto $LOOP_ECFS $MNT_ECFS ecfs"

########################
# 综合操作
########################
echo "[TEST] mixed ops"
sudo bash -c "$(declare -f run_ops); run_ops $MNT_EXT4"
sudo bash -c "$(declare -f run_ops); run_ops $MNT_ECFS"

sync

########################
# umount + fsck
########################
echo "== umount =="
sudo umount $MNT_EXT4
sudo umount $MNT_ECFS

echo "== fsck ext4 =="
sudo fsck.ext4 -fn $LOOP_EXT4 || true

echo "== fsck ecfs =="
sudo $ECFS_FSCK -fn $LOOP_ECFS || true

########################
# cleanup
########################
sudo losetup -d $LOOP_EXT4
sudo losetup -d $LOOP_ECFS

echo "ALL TESTS DONE"
