savedcmd_meta/raft.o := gcc -Wp,-MMD,meta/.raft.o.d -nostdinc -I/usr/src/linux-headers-6.17.0-5-generic/arch/x86/include -I/usr/src/linux-headers-6.17.0-5-generic/arch/x86/include/generated -I/usr/src/linux-headers-6.17.0-5-generic/include -I/usr/src/linux-headers-6.17.0-5-generic/include -I/usr/src/linux-headers-6.17.0-5-generic/arch/x86/include/uapi -I/usr/src/linux-headers-6.17.0-5-generic/arch/x86/include/generated/uapi -I/usr/src/linux-headers-6.17.0-5-generic/include/uapi -I/usr/src/linux-headers-6.17.0-5-generic/include/generated/uapi -include /usr/src/linux-headers-6.17.0-5-generic/include/linux/compiler-version.h -include /usr/src/linux-headers-6.17.0-5-generic/include/linux/kconfig.h -I/usr/src/linux-headers-6.17.0-5-generic/ubuntu/include -include /usr/src/linux-headers-6.17.0-5-generic/include/linux/compiler_types.h -D__KERNEL__ -std=gnu11 -fshort-wchar -funsigned-char -fno-common -fno-PIE -fno-strict-aliasing -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -fcf-protection=none -m64 -falign-jumps=1 -falign-loops=1 -mno-80387 -mno-fp-ret-in-387 -mpreferred-stack-boundary=3 -mskip-rax-setup -march=x86-64 -mtune=generic -mno-red-zone -mcmodel=kernel -mstack-protector-guard-reg=gs -mstack-protector-guard-symbol=__ref_stack_chk_guard -Wno-sign-compare -fno-asynchronous-unwind-tables -mindirect-branch=thunk-extern -mindirect-branch-register -mindirect-branch-cs-prefix -mfunction-return=thunk-extern -fno-jump-tables -mharden-sls=all -fpatchable-function-entry=16,16 -fno-delete-null-pointer-checks -O2 -fno-allow-store-data-races -fstack-protector-strong -fno-omit-frame-pointer -fno-optimize-sibling-calls -ftrivial-auto-var-init=zero -fzero-init-padding-bits=all -fno-stack-clash-protection -fzero-call-used-regs=used-gpr -pg -mrecord-mcount -mfentry -DCC_USING_FENTRY -fmin-function-alignment=16 -fstrict-flex-arrays=3 -fno-strict-overflow -fno-stack-check -fconserve-stack -fno-builtin-wcslen -Wall -Wextra -Wundef -Werror=implicit-function-declaration -Werror=implicit-int -Werror=return-type -Werror=strict-prototypes -Wno-format-security -Wno-trigraphs -Wno-frame-address -Wno-address-of-packed-member -Wmissing-declarations -Wmissing-prototypes -Wframe-larger-than=1024 -Wno-main -Wno-dangling-pointer -Wvla-larger-than=1 -Wno-pointer-sign -Wcast-function-type -Wno-unterminated-string-initialization -Wno-array-bounds -Wno-stringop-overflow -Wno-alloc-size-larger-than -Wimplicit-fallthrough=5 -Werror=date-time -Werror=incompatible-pointer-types -Werror=designated-init -Wenum-conversion -Wunused -Wno-unused-but-set-variable -Wno-unused-const-variable -Wno-packed-not-aligned -Wno-format-overflow -Wno-format-truncation -Wno-stringop-truncation -Wno-override-init -Wno-missing-field-initializers -Wno-type-limits -Wno-shift-negative-value -Wno-maybe-uninitialized -Wno-sign-compare -Wno-unused-parameter -g -gdwarf-5  -fsanitize=bounds-strict -fsanitize=shift -fsanitize=bool -fsanitize=enum    -DMODULE  -DKBUILD_BASENAME='"raft"' -DKBUILD_MODNAME='"ecfs"' -D__KBUILD_MODNAME=kmod_ecfs -c -o meta/raft.o meta/raft.c   ; /usr/src/linux-headers-6.17.0-5-generic/tools/objtool/objtool --hacks=jump_label --hacks=noinstr --hacks=skylake --retpoline --rethunk --sls --stackval --static-call --uaccess --prefix=16 --Werror   --module meta/raft.o

source_meta/raft.o := meta/raft.c

deps_meta/raft.o := \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/compiler-version.h \
    $(wildcard include/config/CC_VERSION_TEXT) \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/kconfig.h \
    $(wildcard include/config/CPU_BIG_ENDIAN) \
    $(wildcard include/config/BOOGER) \
    $(wildcard include/config/FOO) \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/compiler_types.h \
    $(wildcard include/config/DEBUG_INFO_BTF) \
    $(wildcard include/config/PAHOLE_HAS_BTF_TAG) \
    $(wildcard include/config/FUNCTION_ALIGNMENT) \
    $(wildcard include/config/CC_HAS_SANE_FUNCTION_ALIGNMENT) \
    $(wildcard include/config/X86_64) \
    $(wildcard include/config/ARM64) \
    $(wildcard include/config/LD_DEAD_CODE_DATA_ELIMINATION) \
    $(wildcard include/config/LTO_CLANG) \
    $(wildcard include/config/HAVE_ARCH_COMPILER_H) \
    $(wildcard include/config/CC_HAS_COUNTED_BY) \
    $(wildcard include/config/CC_HAS_MULTIDIMENSIONAL_NONSTRING) \
    $(wildcard include/config/UBSAN_INTEGER_WRAP) \
    $(wildcard include/config/CC_HAS_ASM_INLINE) \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/compiler_attributes.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/compiler-gcc.h \
    $(wildcard include/config/MITIGATION_RETPOLINE) \
    $(wildcard include/config/ARCH_USE_BUILTIN_BSWAP) \
    $(wildcard include/config/SHADOW_CALL_STACK) \
    $(wildcard include/config/KCOV) \
    $(wildcard include/config/CC_HAS_TYPEOF_UNQUAL) \
  meta/raft.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/types.h \
    $(wildcard include/config/HAVE_UID16) \
    $(wildcard include/config/UID16) \
    $(wildcard include/config/ARCH_DMA_ADDR_T_64BIT) \
    $(wildcard include/config/PHYS_ADDR_T_64BIT) \
    $(wildcard include/config/64BIT) \
    $(wildcard include/config/ARCH_32BIT_USTAT_F_TINODE) \
  /usr/src/linux-headers-6.17.0-5-generic/include/uapi/linux/types.h \
  /usr/src/linux-headers-6.17.0-5-generic/arch/x86/include/generated/uapi/asm/types.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/uapi/asm-generic/types.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/asm-generic/int-ll64.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/uapi/asm-generic/int-ll64.h \
  /usr/src/linux-headers-6.17.0-5-generic/arch/x86/include/uapi/asm/bitsperlong.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/asm-generic/bitsperlong.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/uapi/asm-generic/bitsperlong.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/uapi/linux/posix_types.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/stddef.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/uapi/linux/stddef.h \
  /usr/src/linux-headers-6.17.0-5-generic/arch/x86/include/asm/posix_types.h \
    $(wildcard include/config/X86_32) \
  /usr/src/linux-headers-6.17.0-5-generic/arch/x86/include/uapi/asm/posix_types_64.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/uapi/asm-generic/posix_types.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/printk.h \
    $(wildcard include/config/MESSAGE_LOGLEVEL_DEFAULT) \
    $(wildcard include/config/CONSOLE_LOGLEVEL_DEFAULT) \
    $(wildcard include/config/CONSOLE_LOGLEVEL_QUIET) \
    $(wildcard include/config/EARLY_PRINTK) \
    $(wildcard include/config/PRINTK) \
    $(wildcard include/config/SMP) \
    $(wildcard include/config/PRINTK_INDEX) \
    $(wildcard include/config/DYNAMIC_DEBUG) \
    $(wildcard include/config/DYNAMIC_DEBUG_CORE) \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/stdarg.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/init.h \
    $(wildcard include/config/MEMORY_HOTPLUG) \
    $(wildcard include/config/HAVE_ARCH_PREL32_RELOCATIONS) \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/build_bug.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/compiler.h \
    $(wildcard include/config/TRACE_BRANCH_PROFILING) \
    $(wildcard include/config/PROFILE_ALL_BRANCHES) \
    $(wildcard include/config/OBJTOOL) \
    $(wildcard include/config/CFI_CLANG) \
  /usr/src/linux-headers-6.17.0-5-generic/arch/x86/include/generated/asm/rwonce.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/asm-generic/rwonce.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/kasan-checks.h \
    $(wildcard include/config/KASAN_GENERIC) \
    $(wildcard include/config/KASAN_SW_TAGS) \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/kcsan-checks.h \
    $(wildcard include/config/KCSAN) \
    $(wildcard include/config/KCSAN_WEAK_MEMORY) \
    $(wildcard include/config/KCSAN_IGNORE_ATOMICS) \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/stringify.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/kern_levels.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/linkage.h \
    $(wildcard include/config/ARCH_USE_SYM_ANNOTATIONS) \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/export.h \
    $(wildcard include/config/MODVERSIONS) \
    $(wildcard include/config/GENDWARFKSYMS) \
  /usr/src/linux-headers-6.17.0-5-generic/arch/x86/include/asm/linkage.h \
    $(wildcard include/config/CALL_PADDING) \
    $(wildcard include/config/MITIGATION_RETHUNK) \
    $(wildcard include/config/MITIGATION_SLS) \
    $(wildcard include/config/FUNCTION_PADDING_BYTES) \
    $(wildcard include/config/UML) \
  /usr/src/linux-headers-6.17.0-5-generic/arch/x86/include/asm/ibt.h \
    $(wildcard include/config/X86_KERNEL_IBT) \
    $(wildcard include/config/FINEIBT_BHI) \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/ratelimit_types.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/bits.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/vdso/bits.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/vdso/const.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/uapi/linux/const.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/uapi/linux/bits.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/overflow.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/limits.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/uapi/linux/limits.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/vdso/limits.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/const.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/uapi/linux/param.h \
  /usr/src/linux-headers-6.17.0-5-generic/arch/x86/include/generated/uapi/asm/param.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/asm-generic/param.h \
    $(wildcard include/config/HZ) \
  /usr/src/linux-headers-6.17.0-5-generic/include/uapi/asm-generic/param.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/spinlock_types_raw.h \
    $(wildcard include/config/DEBUG_SPINLOCK) \
    $(wildcard include/config/DEBUG_LOCK_ALLOC) \
  /usr/src/linux-headers-6.17.0-5-generic/arch/x86/include/asm/spinlock_types.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/asm-generic/qspinlock_types.h \
    $(wildcard include/config/NR_CPUS) \
  /usr/src/linux-headers-6.17.0-5-generic/include/asm-generic/qrwlock_types.h \
  /usr/src/linux-headers-6.17.0-5-generic/arch/x86/include/uapi/asm/byteorder.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/byteorder/little_endian.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/uapi/linux/byteorder/little_endian.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/swab.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/uapi/linux/swab.h \
  /usr/src/linux-headers-6.17.0-5-generic/arch/x86/include/uapi/asm/swab.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/byteorder/generic.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/lockdep_types.h \
    $(wildcard include/config/PROVE_RAW_LOCK_NESTING) \
    $(wildcard include/config/LOCKDEP) \
    $(wildcard include/config/LOCK_STAT) \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/once_lite.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/dynamic_debug.h \
    $(wildcard include/config/JUMP_LABEL) \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/jump_label.h \
    $(wildcard include/config/HAVE_ARCH_JUMP_LABEL_RELATIVE) \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/cleanup.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/err.h \
  /usr/src/linux-headers-6.17.0-5-generic/arch/x86/include/generated/uapi/asm/errno.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/uapi/asm-generic/errno.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/uapi/asm-generic/errno-base.h \
  /usr/src/linux-headers-6.17.0-5-generic/include/linux/args.h \
  /usr/src/linux-headers-6.17.0-5-generic/arch/x86/include/asm/jump_label.h \
    $(wildcard include/config/HAVE_JUMP_LABEL_HACK) \
  /usr/src/linux-headers-6.17.0-5-generic/arch/x86/include/asm/asm.h \
    $(wildcard include/config/KPROBES) \
  /usr/src/linux-headers-6.17.0-5-generic/arch/x86/include/asm/extable_fixup_types.h \
  /usr/src/linux-headers-6.17.0-5-generic/arch/x86/include/asm/nops.h \

meta/raft.o: $(deps_meta/raft.o)

$(deps_meta/raft.o):

meta/raft.o: $(wildcard /usr/src/linux-headers-6.17.0-5-generic/tools/objtool/objtool)
