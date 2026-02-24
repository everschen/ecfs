#!/usr/bin/env python3
import struct
import sys
import os



class Ext4Superblock:
    def __init__(self, data: bytes):
        if len(data) != 1024:
            raise ValueError("Superblock must be exactly 1024 bytes")

        # 基础字段
        self.s_inodes_count = self._u32(data, 0)
        self.s_blocks_count_lo = self._u32(data, 4)
        self.s_r_blocks_count_lo = self._u32(data, 8)
        self.s_free_blocks_count_lo = self._u32(data, 12)
        self.s_free_inodes_count = self._u32(data, 16)
        self.s_first_data_block = self._u32(data, 20)
        self.s_log_block_size = self._u32(data, 24)
        self.s_log_cluster_size = self._u32(data, 28)
        self.s_blocks_per_group = self._u32(data, 32)
        self.s_clusters_per_group = self._u32(data, 36)
        self.s_inodes_per_group = self._u32(data, 40)
        self.s_mtime = self._u32(data, 44)
        self.s_wtime = self._u32(data, 48)
        self.s_mnt_count = self._u16(data, 52)
        self.s_max_mnt_count = self._u16(data, 54)
        self.s_magic = self._u16(data, 56)
        self.s_state = self._u16(data, 58)
        self.s_errors = self._u16(data, 60)
        self.s_minor_rev_level = self._u16(data, 62)
        self.s_lastcheck = self._u32(data, 64)
        self.s_checkinterval = self._u32(data, 68)
        self.s_creator_os = self._u32(data, 72)
        self.s_rev_level = self._u32(data, 76)
        self.s_def_resuid = self._u16(data, 80)
        self.s_def_resgid = self._u16(data, 82)

        # ext4 扩展字段
        self.s_first_ino = self._u32(data, 84)
        self.s_inode_size = self._u16(data, 88)
        self.s_block_group_nr = self._u16(data, 90)
        self.s_feature_compat = self._u32(data, 92)
        self.s_feature_incompat = self._u32(data, 96)
        self.s_feature_ro_compat = self._u32(data, 100)

        # 64bit 支持
        self.s_blocks_count_hi = self._u32(data, 150)
        self.s_r_blocks_count_hi = self._u32(data, 154)
        self.s_free_blocks_count_hi = self._u32(data, 158)

        self.block_size = 1024 << self.s_log_block_size

        # 组合 64bit block 数
        self.blocks_count = (
            (self.s_blocks_count_hi << 32) | self.s_blocks_count_lo
        )

        if self.s_magic != 0xEF53 and self.s_magic != 0xECF3:
            raise ValueError("Not ext4/ecfs: self.s_magic=%x", self.s_magic)

        self.is_ext4=False
        self.is_ecfs=False
        if self.s_magic == 0xEF53:
            self.is_ext4=True
        elif self.s_magic == 0xECF3:
            self.is_ecfs=True
            self.s_node_id = self._u16(data, 716)
            self.s_disk_id = self._u16(data, 718)

    def _u16(self, data, offset):
        return struct.unpack_from("<H", data, offset)[0]

    def _u32(self, data, offset):
        return struct.unpack_from("<I", data, offset)[0]

    def summary(self):
        if self.is_ext4:
            print("========= EXT4 SUPERBLOCK =========")
        if self.is_ecfs:
            print("========= ECFS SUPERBLOCK =========")
        print(f"Inodes count         : {self.s_inodes_count}")
        print(f"Blocks count         : {self.blocks_count}")
        print(f"Free blocks          : {self.s_free_blocks_count_lo}")
        print(f"Free inodes          : {self.s_free_inodes_count}")
        print(f"First data block     : {self.s_first_data_block}")
        print(f"Block size           : {self.block_size}")
        print(f"Blocks per group     : {self.s_blocks_per_group}")
        print(f"Inodes per group     : {self.s_inodes_per_group}")
        print(f"Inode size           : {self.s_inode_size}")
        print(f"Feature compat       : 0x{self.s_feature_compat:x}")
        print(f"Feature incompat     : 0x{self.s_feature_incompat:x}")
        print(f"Feature ro compat    : 0x{self.s_feature_ro_compat:x}")
        if self.is_ecfs:
            print(f"Ecfs node id         : {self.s_node_id}")
            print(f"Ecfs disk id         : {self.s_disk_id}")
        print("===================================")


def read_superblock(device_path):
    with open(device_path, "rb") as f:
        f.seek(1024)
        data = f.read(1024)

    return Ext4Superblock(data)


if __name__ == "__main__":
    ECFS_IMG = "~/test_ecfs.img"
    EXT4_IMG = "~/test_ext4.img"

    if len(sys.argv) >= 2:
        img_path = sys.argv[1]
        if img_path.lower() == "ext4":
            img_path = EXT4_IMG
        if img_path.lower() == "ecfs":
            img_path = ECFS_IMG
    else:
        img_path = os.environ.get('IMG')
        if img_path is None:
            if len(sys.argv) < 2:
                img_path = ECFS_IMG

    try:
        img_path = os.path.expanduser(img_path)
        sb = read_superblock(img_path)
        sb.summary()
    except Exception as e:
        print("Error:", e)
        sys.exit(1)
