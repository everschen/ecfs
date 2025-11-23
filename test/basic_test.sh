
# 编译

cd /home/evers/linux-6.17.0/fs/ecfs

make

# 加载
sudo insmod ecfs.ko

# 创建镜像
#sudo dd if=/dev/zero of=/home/evers/test.img bs=1M count=16318

LOOP=$(sudo losetup -f --show /home/evers/test.img)

sudo /home/evers/e2fsprogs/misc/mke2fs -t ext4 -i 32768 $LOOP

# 挂载
sudo mkdir -p /mnt/ecfs
sudo mount -t ecfs $LOOP /mnt/ecfs

# 测试
ls -la /mnt/ecfs
sudo mkdir /mnt/ecfs/dir
sudo touch /mnt/ecfs/file.txt
echo "Hello ECFS!" | sudo tee /mnt/ecfs/file.txt
sudo cat /mnt/ecfs/file.txt
ls -la /mnt/ecfs/dir

# 卸载

#sudo losetup -a

sudo umount /mnt/ecfs
sudo losetup -d $LOOP
sudo rmmod ecfs

cd /home/evers/linux-6.17.0/fs/ecfs
