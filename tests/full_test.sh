#!/bin/bash
set -euo pipefail

########################
# 配置
########################

relink() {
    local link_path="$2"
    local new_target="$1"

    # 1. 检查是否真的是符号链接
    if [ -L "$link_path" ]; then
        rm -f "$link_path"
    fi

    ln -sf "$new_target" "$link_path"
}

TEST_PATH=$HOME
inode_start_block=37

sudo rm -f /tmp/fs_debug.log
sudo dmesg -C

SIZE=128M

# 如果没有传参数，默认使用 ecfs
MODE="${1:-ecfs}"

case "$MODE" in
    ecfs|ext4)
        echo "Selected mode: $MODE"
        ;;
    *)
        echo "Usage: $0 [ecfs|ext4]   (default: ecfs)"
        exit 1
        ;;
esac

if [ "$MODE" == "ecfs" ]; then
    ECFS_DIR=$TEST_PATH/linux-6.17.0/fs/ecfs
    E2FSPROGS=$TEST_PATH/e2fsprogs/
    MKE2FS=$E2FSPROGS/misc/mke2fs
    E2FS_PATH=$E2FSPROGS/misc/
    IMG=$TEST_PATH/test_ecfs.img
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
      echo "ecfs loaded and refcnt = 0, rmmod and insmod"
      sudo rmmod ecfs
      sudo insmod ecfs.ko
  else
      echo "ecfs loaded but refcnt != 0"
      exit 1
  fi
fi

cd $E2FSPROGS
make -j6

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

  mkdir "$M/rmdir_test"
  P_LINK_BEFORE=$(stat -c %h "$M")
  DIR_INO=$(stat -c %i "$M/rmdir_test")

  rmdir "$M/rmdir_test" \
    || fail "$NAME: rmdir failed"

  P_LINK_AFTER=$(stat -c %h "$M")
  test $((P_LINK_BEFORE - 1)) -eq "$P_LINK_AFTER" \
    || fail "$NAME: parent link not decremented"

  test ! -e "$M/rmdir_test" \
    || fail "$NAME: dir entry still exists"

  echo "[PASS][$NAME] Test-2 rmdir"
}

########################
# Test-3: unlink 自动检测
########################
test_unlink_auto() {
  local M=$1
  local NAME=$2
  echo "[TEST-3][$NAME] unlink correctness"

  echo "hello" > "$M/unlink_test"
  FILE_INO=$(stat -c %i "$M/unlink_test")
  FILE_LINK=$(stat -c %h "$M/unlink_test")
  test "$FILE_LINK" -eq 1 \
    || fail "$NAME: initial link count != 1"

  P_LINK_BEFORE=$(stat -c %h "$M")
  rm "$M/unlink_test" \
    || fail "$NAME: unlink failed"

  test ! -e "$M/unlink_test" \
    || fail "$NAME: dir entry still exists"

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

  # 场景 A: 同目录
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

  # 场景 B: 跨目录
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

  # 场景 C: 覆盖已有文件
  echo "C1" > "$M/rn_c1"
  echo "C2" > "$M/rn_c2"
  INO_C1=$(stat -c %i "$M/rn_c1")
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

  echo "HL" > "$M/hl_src"
  SRC_INO=$(stat -c %i "$M/hl_src")
  test "$(stat -c %h "$M/hl_src")" -eq 1 \
    || fail "$NAME: initial link count != 1"

  ln "$M/hl_src" "$M/hl_dst" \
    || fail "$NAME: hard link failed"
  test "$(stat -c %h "$M/hl_src")" -eq 2 \
    || fail "$NAME: link count not incremented after link"
  test "$(stat -c %i "$M/hl_dst")" -eq "$SRC_INO" \
    || fail "$NAME: hard link inode mismatch"

  rm "$M/hl_src"
  test "$(stat -c %h "$M/hl_dst")" -eq 1 \
    || fail "$NAME: link count not decremented after unlink"

  rm "$M/hl_dst"

  echo "[PASS][$NAME] Test-5 hard link"
}

########################
# Test-6: crash consistency 自动检测
########################
test_crash_auto() {
  local LOOP=$1
  local M=$2
  local NAME=$3
  local FSCK=$4

  echo "[TEST-6][$NAME] crash consistency"

  #sudo mount $LOOP $M

  mkdir "$M/crash_dir"
  echo "file" > "$M/crash_dir/file1"
  ln "$M/crash_dir/file1" "$M/crash_dir/file2"
  mv "$M/crash_dir/file2" "$M/crash_dir/file3"
  rm "$M/crash_dir/file1"
  rmdir "$M/crash_dir/file3" || true

  sudo umount -l $M || true
  sync

  echo $FSCK
  sudo $FSCK -fn $LOOP || fail "$NAME: fsck failed after simulated crash"


  echo "[PASS][$NAME] Test-6 crash consistency"
}

########################
# mixed stress ops
########################
run_ops() {
  local M=$1
  local NAME=$2
  echo "[mixed stress ops][$NAME]"

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

  echo "[PASS][$NAME] mixed stress ops"
}

print_title() {
    title=$1
    echo ""
    echo "====================== $title ======================"

}

########################
# 主流程
########################

print_title "prepare images"
# truncate -s $SIZE $IMG
LOOP=$(sudo losetup -f --show $IMG)
sudo wipefs -a "$LOOP"


print_title ${E2FS_PATH}mke2fs
sudo ${E2FS_PATH}mke2fs -t ext4 -b 4096 -I 256 -i 32768 -E lazy_itable_init=0,lazy_journal_init=0 $LOOP
#sudo mkfs.ecfs $LOOP


print_title mount
sudo mkdir -p $MNT
echo "sudo mount -t $MODE $LOOP $MNT"
sudo mount -t $MODE $LOOP $MNT

########################
# Run all tests
########################

# Test-1
print_title "Test-1"
echo "sudo bash -c (declare -f fail test_mkdir_auto); test_mkdir_auto $MNT $MODE"
sudo bash -c "$(declare -f fail test_mkdir_auto); test_mkdir_auto $MNT $MODE"

# Test-2
print_title Test-2
sudo bash -c "$(declare -f fail test_rmdir_auto); test_rmdir_auto $MNT $MODE"

# # Test-3
print_title Test-3
sudo bash -c "$(declare -f fail test_unlink_auto); test_unlink_auto $MNT $MODE"

# # Test-4
print_title Test-4
sudo bash -c "$(declare -f fail test_rename_auto); test_rename_auto $MNT $MODE"

# # Test-5
print_title Test-5
sudo bash -c "$(declare -f fail test_hardlink_auto); test_hardlink_auto $MNT $MODE"


print_title "mixed stress ops"
#mixed ops
sudo bash -c "$(declare -f run_ops); run_ops $MNT $MODE"


# # Test-6
print_title Test-6
sudo bash -c "$(declare -f fail test_crash_auto); test_crash_auto $LOOP $MNT $MODE $FSCK"


print_title "All testcase down"

#sync

#umount done in test-6
# umount + fsck
# print_title umount
# echo "sudo umount $MNT"
# sudo umount $MNT

print_title "fsck $MODE"
echo "sudo $FSCK -fn $LOOP || true"
sudo $FSCK -fn $LOOP || true

echo "test"

# cleanup
sudo losetup -d $LOOP

echo "ALL TESTS DONE"
