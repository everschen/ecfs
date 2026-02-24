#!/usr/bin/env python3
import struct
import sys,os
import math


EXT4_FEATURE_INCOMPAT_64BIT = 0x80
EXT4_FEATURE_INCOMPAT_EXTENTS = 0x40


# ================= SUPERBLOCK =================
class Ext4Superblock:
    def __init__(self, data: bytes):
        self.s_inodes_count = self._u32(data, 0)
        self.s_blocks_count_lo = self._u32(data, 4)
        self.s_log_block_size = self._u32(data, 24)
        self.s_blocks_per_group = self._u32(data, 32)
        self.s_inodes_per_group = self._u32(data, 40)
        self.s_magic = self._u16(data, 56)
        self.s_inode_size = self._u16(data, 88)
        self.s_feature_incompat = self._u32(data, 96)
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


# ================= GROUP DESC =================
class Ext4GroupDescriptor:
    def __init__(self, data: bytes, is_64bit=False):
        self.bg_inode_table_lo = self._u32(data, 8)

        if is_64bit:
            self.bg_inode_table_hi = self._u32(data, 40)
        else:
            self.bg_inode_table_hi = 0

        self.inode_table = (
            (self.bg_inode_table_hi << 32) |
            self.bg_inode_table_lo
        )

    def _u32(self, data, offset):
        return struct.unpack_from("<I", data, offset)[0]


# ================= INODE =================
class Ext4Inode:
    def __init__(self, data: bytes):
        self.i_mode = self._u16(data, 0)
        self.i_uid = self._u16(data, 2)
        self.i_size_lo = self._u32(data, 4)
        self.i_atime = self._u32(data, 8)
        self.i_ctime = self._u32(data, 12)
        self.i_mtime = self._u32(data, 16)
        self.i_gid = self._u16(data, 24)
        self.i_links_count = self._u16(data, 26)
        self.i_blocks_lo = self._u32(data, 28)
        self.i_flags = self._u32(data, 32)

        # extent / block array
        self.i_block = data[40:40+60]

        # ext4 大文件 size
        self.i_size_high = self._u32(data, 108)
        self.size = (self.i_size_high << 32) | self.i_size_lo

    def _u16(self, data, offset):
        return struct.unpack_from("<H", data, offset)[0]

    def _u32(self, data, offset):
        return struct.unpack_from("<I", data, offset)[0]

    def print_summary(self):
        print("===== INODE =====")
        print("Mode        :", hex(self.i_mode))
        print("UID         :", self.i_uid)
        print("GID         :", self.i_gid)
        print("Size        :", self.size)
        print("Links       :", self.i_links_count)
        print("Blocks (512b):", self.i_blocks_lo)
        print("Flags       :", hex(self.i_flags))
        print("=================")

    def parse_extent_header(self):
        magic = struct.unpack_from("<H", self.i_block, 0)[0]
        if magic != 0xF30A:
            print("Not extent format")
            return

        entries = struct.unpack_from("<H", self.i_block, 2)[0]
        depth = struct.unpack_from("<H", self.i_block, 6)[0]

        print("Extent header:")
        print("  Entries:", entries)
        print("  Depth  :", depth)

    def get_extents(self, f, sb):
        eh_magic, eh_entries, eh_max, eh_depth = struct.unpack_from(
            "<HHHH", self.i_block, 0
        )

        if eh_magic != 0xF30A:
            print("Not extent-based inode")
            return []

        extents = []

        if eh_depth == 0:
            # 直接 leaf
            for i in range(eh_entries):
                off = 12 + i * 12
                ee_block, ee_len, ee_start_hi, ee_start_lo = struct.unpack_from(
                    "<IHHI", self.i_block, off
                )
                phys = (ee_start_hi << 32) | ee_start_lo
                extents.append((ee_block, ee_len, phys))
        else:
            # 需要递归
            for i in range(eh_entries):
                off = 12 + i * 12
                ei_block, ei_leaf_lo, ei_leaf_hi = struct.unpack_from(
                    "<IIH", self.i_block, off
                )
                child = (ei_leaf_hi << 32) | ei_leaf_lo
                extents.extend(
                    parse_extent_tree(f, sb, child, eh_depth - 1)
                )

        return extents

# ================= READ FUNCTIONS =================
def read_superblock(f):
    f.seek(1024)
    return Ext4Superblock(f.read(1024))


def read_gdt(f, sb):
    is_64bit = bool(sb.s_feature_incompat & EXT4_FEATURE_INCOMPAT_64BIT)
    desc_size = 64 if is_64bit else 32

    if sb.block_size == 1024:
        gdt_offset = 2 * sb.block_size
    else:
        gdt_offset = sb.block_size

    f.seek(gdt_offset)

    groups = []
    for _ in range(sb.groups_count):
        data = f.read(desc_size)
        groups.append(Ext4GroupDescriptor(data, is_64bit))
    return groups


def read_inode(f, sb, groups, inode_no):
    inode_index = inode_no - 1
    group = inode_index // sb.s_inodes_per_group
    index = inode_index % sb.s_inodes_per_group

    inode_table_block = groups[group].inode_table

    inode_offset = (
        inode_table_block * sb.block_size +
        index * sb.s_inode_size
    )

    f.seek(inode_offset)
    data = f.read(sb.s_inode_size)

    return Ext4Inode(data)

def parse_extent_tree(f, sb, block_num, depth):
    """
    递归解析 extent tree block
    """
    offset = block_num * sb.block_size
    f.seek(offset)
    data = f.read(sb.block_size)

    eh_magic, eh_entries, eh_max, eh_depth = struct.unpack_from("<HHHH", data, 0)

    if eh_magic != 0xF30A:
        raise ValueError("Bad extent header magic")

    extents = []

    if eh_depth == 0:
        # leaf
        for i in range(eh_entries):
            off = 12 + i * 12
            ee_block, ee_len, ee_start_hi, ee_start_lo = struct.unpack_from(
                "<IHHI", data, off
            )

            phys_block = (ee_start_hi << 32) | ee_start_lo
            extents.append((ee_block, ee_len, phys_block))

    else:
        # index node
        for i in range(eh_entries):
            off = 12 + i * 12
            ei_block, ei_leaf_lo, ei_leaf_hi = struct.unpack_from(
                "<IIH", data, off
            )

            child_block = (ei_leaf_hi << 32) | ei_leaf_lo
            extents.extend(
                parse_extent_tree(f, sb, child_block, eh_depth - 1)
            )

    return extents

def parse_directory_block(data, is_ecfs):
    offset = 0
    entries = []

    if not is_ecfs:
        fmt = "<IHBb"  #inode_size == 4
    else:
        fmt = "<QHBb"  #inode_size == 8


    header_size = struct.calcsize(fmt)

    while offset + header_size <= len(data):
        fields = struct.unpack_from(fmt, data, offset)

        inode = fields[0]
        rec_len = fields[1]
        name_len = fields[2]
        file_type = fields[3]

        if rec_len == 0:
            break

        if inode != 0:
            name_offset = offset + header_size
            name = data[name_offset:name_offset + name_len].decode(
                errors="ignore"
            )

            entries.append({
                "inode": inode,
                "name": name,
                "type": file_type,
            })

        offset += rec_len

    return entries

def list_directory(f, sb, inode, is_ecfs):
    extents = inode.get_extents(f, sb)

    all_entries = []

    for logical, length, physical in extents:
        #print(logical, length, physical)
        for i in range(length):
            block_num = physical + i
            offset = block_num * sb.block_size

            f.seek(offset)
            data = f.read(sb.block_size)
            #print(i, offset, data)

            entries = parse_directory_block(data, is_ecfs)
            #print(i, offset, entries)
            all_entries.extend(entries)

    return all_entries

def read_journal_inode(f, sb, groups):
    # inode 8 通常是 journal
    return read_inode(f, sb, groups, 8)

def read_journal_blocks(f, sb, inode):
    extents = inode.get_extents(f, sb)

    blocks = []

    for logical, length, physical in extents:
        for i in range(length):
            blocks.append(physical + i)

    return blocks

def parse_jbd2_header(data):
    h_magic, h_blocktype, h_sequence = struct.unpack_from(">III", data, 0)

    if h_magic != 0xC03B3998:
        return None

    return {
        "type": h_blocktype,
        "sequence": h_sequence
    }

def parse_descriptor_block(data, block_size):
    offset = 12
    tags = []

    while offset + 8 <= block_size:
        blocknr, flags = struct.unpack_from(">II", data, offset)

        if blocknr == 0:
            break

        tags.append((blocknr, flags))
        offset += 8

    return tags

def parse_journal(f, sb, journal_inode):
    journal_blocks = read_journal_blocks(f, sb, journal_inode)

    print("\n=== Journal Analysis ===\n")

    for blk in journal_blocks:
        f.seek(blk * sb.block_size)
        data = f.read(sb.block_size)

        header = parse_jbd2_header(data)

        if not header:
            continue

        block_type = header["type"]
        seq = header["sequence"]

        print(f"Journal block {blk}: type={block_type} seq={seq}")

        if block_type == 1:
            tags = parse_descriptor_block(data, sb.block_size)
            print(f"  Descriptor with {len(tags)} tags")
        elif block_type == 2:
            print("  Commit block")
        elif block_type == 5:
            print("  Revoke block")


# ================= MAIN =================
def main(path, inode_no=2):
    with open(path, "rb") as f:
        sb = read_superblock(f)
        groups = read_gdt(f, sb)

        inode = read_inode(f, sb, groups, inode_no)

        inode.print_summary()
        inode.parse_extent_header()

        extents = inode.get_extents(f, sb)

        print("\nExtent Mapping:")
        for logical, length, physical in extents:
            print(
                f"Logical block {logical} "
                f"-> Physical block {physical} "
                f"(len={length})"
            )

        if (inode.i_mode & 0xF000) == 0x4000:
            print("\nDirectory listing:\n")

            entries = list_directory(f, sb, inode, sb.is_ecfs)

            for e in entries:
                if sb.is_ecfs:
                    hex_str = f"{e['inode']:016x}"
                    a = int(hex_str[0:4], 16)
                    b = int(hex_str[4:8], 16)
                    c = int(hex_str[8:16], 16)
                    formatted = f"{a}-{b}-{c}"
                    print(f"{formatted:8}  {e['type']}  {e['name']}")
                else:
                    print(f"{e['inode']:8}  {e['type']}  {e['name']}")
        else:
            print("Not a directory")

        journal_inode = read_journal_inode(f, sb, groups)
        parse_journal(f, sb, journal_inode)


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

    inode_no = int(sys.argv[2]) if len(sys.argv) > 2 else 2
    main(img_path, inode_no)