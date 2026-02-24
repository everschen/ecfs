#!/usr/bin/env python3
import struct
import sys,os
import math


class Ext4Superblock:
    def __init__(self, data: bytes):
        if len(data) != 1024:
            raise ValueError("Invalid superblock size")

        self.s_inodes_count = self._u32(data, 0)
        self.s_blocks_count_lo = self._u32(data, 4)
        self.s_free_blocks_count_lo = self._u32(data, 12)
        self.s_free_inodes_count = self._u32(data, 16)
        self.s_first_data_block = self._u32(data, 20)
        self.s_log_block_size = self._u32(data, 24)
        self.s_blocks_per_group = self._u32(data, 32)
        self.s_inodes_per_group = self._u32(data, 40)
        self.s_magic = self._u16(data, 56)
        self.s_inode_size = self._u16(data, 88)
        self.s_feature_incompat = self._u32(data, 96)

        # 64bit support
        self.s_blocks_count_hi = self._u32(data, 150)

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

        self.block_size = 1024 << self.s_log_block_size

        self.blocks_count = (
            (self.s_blocks_count_hi << 32) |
            self.s_blocks_count_lo
        )

        self.groups_count = math.ceil(
            self.blocks_count / self.s_blocks_per_group
        )

    def _u16(self, data, offset):
        return struct.unpack_from("<H", data, offset)[0]

    def _u32(self, data, offset):
        return struct.unpack_from("<I", data, offset)[0]


class Ext4GroupDescriptor:
    def __init__(self, data: bytes, is_64bit=False):
        self.bg_block_bitmap_lo = self._u32(data, 0)
        self.bg_inode_bitmap_lo = self._u32(data, 4)
        self.bg_inode_table_lo = self._u32(data, 8)
        self.bg_free_blocks_count_lo = self._u16(data, 12)
        self.bg_free_inodes_count_lo = self._u16(data, 14)
        self.bg_used_dirs_count_lo = self._u16(data, 16)

        if is_64bit:
            self.bg_block_bitmap_hi = self._u32(data, 32)
            self.bg_inode_bitmap_hi = self._u32(data, 36)
            self.bg_inode_table_hi = self._u32(data, 40)
        else:
            self.bg_block_bitmap_hi = 0
            self.bg_inode_bitmap_hi = 0
            self.bg_inode_table_hi = 0

        self.block_bitmap = (
            (self.bg_block_bitmap_hi << 32) |
            self.bg_block_bitmap_lo
        )
        self.inode_bitmap = (
            (self.bg_inode_bitmap_hi << 32) |
            self.bg_inode_bitmap_lo
        )
        self.inode_table = (
            (self.bg_inode_table_hi << 32) |
            self.bg_inode_table_lo
        )

    def _u16(self, data, offset):
        return struct.unpack_from("<H", data, offset)[0]

    def _u32(self, data, offset):
        return struct.unpack_from("<I", data, offset)[0]


def read_superblock(f):
    f.seek(1024)
    data = f.read(1024)
    return Ext4Superblock(data)


def read_gdt(f, sb):
    # 判断是否启用 64bit feature
    EXT4_FEATURE_INCOMPAT_64BIT = 0x80
    is_64bit = bool(sb.s_feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT)

    desc_size = 64 if is_64bit else 32

    # GDT 位置
    if sb.block_size == 1024:
        gdt_offset = 2 * sb.block_size
    else:
        gdt_offset = sb.block_size

    f.seek(gdt_offset)

    groups = []
    for i in range(sb.groups_count):
        data = f.read(desc_size)
        gd = Ext4GroupDescriptor(data, is_64bit)
        groups.append(gd)

    return groups


def main(path):
    with open(path, "rb") as f:
        sb = read_superblock(f)

        print("Block size:", sb.block_size)
        print("Blocks count:", sb.blocks_count)
        print("Groups count:", sb.groups_count)
        print("Inodes per group:", sb.s_inodes_per_group)
        print()

        groups = read_gdt(f, sb)

        for i, g in enumerate(groups[:5]):  # 只打印前5个
            print(f"Group {i}:")
            print("  Block bitmap :", g.block_bitmap)
            print("  Inode bitmap :", g.inode_bitmap)
            print("  Inode table  :", g.inode_table)
            print("  Free blocks  :", g.bg_free_blocks_count_lo)
            print("  Free inodes  :", g.bg_free_inodes_count_lo)
            print()


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

    img_path = os.path.expanduser(img_path)

    main(img_path)