savedcmd_ecfs.o := ld -m elf_x86_64 -z noexecstack --no-warn-rwx-segments   -r -o ecfs.o @ecfs.mod 
