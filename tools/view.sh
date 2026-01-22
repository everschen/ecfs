#you can source this file in .bashrc
#source path_to_this/view.sh


_view_common() {
    local start_bytes num_bytes disk_idx array_idx
    local part drive cmd

    start_bytes=$1    # 起始偏移（字节）
    num_bytes=$2      # 读取长度（字节）
    disk_idx=$3       # 磁盘编号（可选）
    array_idx=$4      # isi array 编号（可选）

    if [[ -z "$start_bytes" || -z "$num_bytes" ]]; then
        echo "Usage: _view_common <start_bytes> <num_bytes> [disk_idx] [array_idx]"
        return 1
    fi

    # 计算设备
    # if [[ -z "$disk_idx" ]]; then
    #     drive="/dev/da7p2"
    # else
    #     part=$((7 - disk_idx))
    #     drive="/dev/da${part}p2"
    # fi
    drive="${IMG:-/home/evers/test.img}"


    # 构造命令（不使用 eval）
    if [[ -n "$array_idx" ]]; then
        cmd=(exe_cmd_from_other_node -n "$array_idx" hexdump -s "$start_bytes" -C -n "$num_bytes" "$drive")
    else
        cmd=(hexdump -s "$start_bytes" -C -n "$num_bytes" "$drive")
    fi

    echo "${cmd[@]}"
    "${cmd[@]}"
}

viewa() {
    # start = 字节偏移
    # blocks = 512B
    _view_common "$1" "$(( $2 * 512 ))" "$3" "$4"
}

viewb() {
    if [[ -z "$1" ]]; then
        echo "Usage: viewb <start_block> [blocks=1] [disk_idx] [array_idx]"
        return 1
    fi

    # 如果第二个参数为空，默认值为 1
    local blocks=${2:-1}

    local offset=$(( $1 * 4096 ))

    # 调用底层查看函数
    _view_common \
        "$offset" \
        "$(( blocks * 4096 ))" \
        "$3" "$4"
}

inode() {
    local inode_index inode_size block_size start_block start_bytes num_bytes disk_idx array_idx

    inode_index=$1      # inode 序号，从 1 开始 
    disk_idx=$2         # 可选，默认 da7p2
    array_idx=$3        # 可选，isi array

    inode_size=256      # bytes
    block_size=4096     # bytes
    #inode_start_block=1059
    inode_start_address=$(( inode_start_block * block_size ))


    if [[ -z "$inode_index" ]]; then
        echo "Usage: view_inode <inode_index> [disk_idx] [array_idx]"
        return 1
    fi

    # inode 在 inode table 的字节偏移
    start_bytes=$(( (inode_index - 1) * inode_size + inode_start_address ))

    # 为了方便，读取完整 block（至少 4096 bytes）
    # 也可以只读取 inode_size bytes
    num_bytes=$inode_size

    # 调用 _view_common 查看
    _view_common "$start_bytes" "$num_bytes" "$disk_idx" "$array_idx"
}

# 查看文件系统头信息（superblock 信息）
drive="${IMG:-/home/evers/test.img}"

E2FS_PATH="${E2FS_PATH-/home/evers/e2fsprogs/misc/}"

E2FS="dumpe2fs"


alias va=viewa
alias vb=viewb

alias he='echo "$drive"; $E2FS_PATH$E2FS -h "$drive"'

# 查看文件系统组信息（group descriptor 信息）
alias gr='echo $E2FS_PATH$E2FS "$drive"; $E2FS_PATH$E2FS "$drive" | less'

