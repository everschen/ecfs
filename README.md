# ECFS - a kernel space scalable distributed file system

### Development Plan

- Phase one: one node, one disk (2026-02-20 done)
    - gid, global inode, global block, design/code ready
    - basic test pass (file create, directory create, ls)
    - full test pass
        - test_mkdir_auto
        - test_rmdir_auto
        - test_unlink_auto
        - test_rename_auto
        - test_hardlink_auto
        - mixed stress ops
        - test_crash_auto
    - fsck test pass

- Phase two: one node, two disks (ongoing)
    - support for two disks
    - test tools for ecfs


- Phase three: two nodes, two disks for each node
    - RPC system ready
