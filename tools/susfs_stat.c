// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_stat - a 64-bit client that PRINTs what newfstatat(79), fstat(80) and statx(291) return.
 *
 * Why this exists.  The kstat spoofing is verified with `ls -li` and `toybox stat` on the device, and
 * both of those go through newfstatat(79) only.  fstat(80) fills the same struct stat but from an fd,
 * and statx(291) fills a DIFFERENT struct (struct statx) with a mask contract that says which fields
 * the kernel actually filled - neither is reachable from a shell, and there is no strace on the
 * device.  `ls`, `toybox stat` and a 32-bit compat client therefore cannot tell "fstat/statx are
 * spoofed" from "they are not", which is how a feature can look broken (or look fine) without anyone
 * having measured it.
 *
 * Same freestanding shape as tools/susfs_sc.c and tools/susfs_compat_stat.c: no libc, its own
 * _start, static-pie, syscalls through inline asm.  Android rejects non-PIE executables and the DDK
 * container has no bionic sysroot, so this is the only way it can be built there.
 *
 * Build (see .github/workflows/build-ddk.yml):
 *
 *   clang --target=aarch64-linux-gnu -O2 -nostdlib -static-pie -fno-stack-protector \
 *         -fno-builtin -fuse-ld=lld -Wl,-e,_start -o susfs_stat tools/susfs_stat.c
 *
 * Usage:
 *
 *   susfs_stat <path> [mask_hex]
 *
 *     <path>      the path to stat (fstat()/statx(AT_EMPTY_PATH) use it via an open fd)
 *     [mask_hex]  statx's request mask, e.g. 7ff (STATX_BASIC_STATS, the default) or 7fff
 *
 * Every line is `key=value` and printed with one syscall, so a test script can grep/compare:
 *
 *   newfstatat: rc=0 ino=... dev=... nlink=... size=... blocks=... blksize=... mtime=...
 *   fstat     : rc=0 ino=... ...                       (same fields, fd-based)
 *   statx     : rc=0 mask=0x7ff blksize=4096 nlink=1 ino=... size=... blocks=... dev=maj:min atime=... mtime=... ctime=...
 *
 * The statx mask is printed because "the field is spoofed but the mask does not say so" (or the
 * reverse) is exactly the inconsistency a checker looks for, and it is also what tells this tool
 * whether the kernel filled a field the caller asked for.
 */

#include <stddef.h>

/* stddef.h for size_t only (the static_asserts below need it); clang's freestanding headers
 * provide it, and it pulls in no libc code. */
#include <stddef.h>

typedef unsigned long long u64;
typedef long long s64;
typedef unsigned int u32;
typedef int s32;

#define SYS_write	64
#define SYS_openat	56
#define SYS_close	57
#define SYS_newfstatat	79
#define SYS_fstat	80
#define SYS_statx	291
#define SYS_sched_setaffinity 122

#define AT_FDCWD		(-100)
#define AT_EMPTY_PATH		0x1000
#define O_RDONLY		0

/* STATX_* request bits (include/uapi/linux/stat.h). */
#define STATX_BASIC_STATS	0x000007ffu

/* arm64 asm-generic struct stat (128 bytes). */
struct stat_native {
	u64 st_dev;		/* 0  */
	u64 st_ino;		/* 8  */
	u32 st_mode;		/* 16 */
	u32 st_nlink;		/* 20 */
	u32 st_uid;		/* 24 */
	u32 st_gid;		/* 28 */
	u64 st_rdev;		/* 32 */
	u64 __pad1;		/* 40 */
	s64 st_size;		/* 48 */
	s32 st_blksize;		/* 56 */
	s32 __pad2;		/* 60 */
	s64 st_blocks;		/* 64 */
	s64 st_atime;		/* 72 */
	u64 st_atime_nsec;	/* 80 */
	s64 st_mtime;		/* 88 */
	u64 st_mtime_nsec;	/* 96 */
	s64 st_ctime;		/* 104 */
	u64 st_ctime_nsec;	/* 112 */
	u32 __unused4;		/* 120 */
	u32 __unused5;		/* 124 */
};

_Static_assert(sizeof(struct stat_native) == 128, "native struct stat size");
_Static_assert(__builtin_offsetof(struct stat_native, st_ino) == 8, "st_ino offset");
_Static_assert(__builtin_offsetof(struct stat_native, st_nlink) == 20, "st_nlink offset");
_Static_assert(__builtin_offsetof(struct stat_native, st_size) == 48, "st_size offset");
_Static_assert(__builtin_offsetof(struct stat_native, st_blocks) == 64, "st_blocks offset");

/* include/uapi/linux/stat.h: struct statx, 256 bytes. */
struct statx_timestamp {
	s64 tv_sec;
	u32 tv_nsec;
	s32 __reserved;
};

struct statx {
	u32 stx_mask;			/* 0x00 */
	u32 stx_blksize;		/* 0x04 */
	u64 stx_attributes;		/* 0x08 */
	u32 stx_nlink;			/* 0x10 */
	u32 stx_uid;			/* 0x14 */
	u32 stx_gid;			/* 0x18 */
	unsigned short stx_mode;	/* 0x1c */
	unsigned short __spare0[1];	/* 0x1e */
	u64 stx_ino;			/* 0x20 */
	u64 stx_size;			/* 0x28 */
	u64 stx_blocks;			/* 0x30 */
	u64 stx_attributes_mask;	/* 0x38 */
	struct statx_timestamp stx_atime;	/* 0x40 */
	struct statx_timestamp stx_btime;	/* 0x50 */
	struct statx_timestamp stx_ctime;	/* 0x60 */
	struct statx_timestamp stx_mtime;	/* 0x70 */
	u32 stx_rdev_major;		/* 0x80 */
	u32 stx_rdev_minor;		/* 0x84 */
	u32 stx_dev_major;		/* 0x88 */
	u32 stx_dev_minor;		/* 0x8c */
	u64 stx_mnt_id;			/* 0x90 */
	u32 stx_dio_mem_align;		/* 0x98 */
	u32 stx_dio_offset_align;	/* 0x9c */
	u64 __spare3[12];		/* 0xa0 */
};

_Static_assert(sizeof(struct statx) == 256, "struct statx size");
_Static_assert(__builtin_offsetof(struct statx, stx_mask) == 0x00, "stx_mask offset");
_Static_assert(__builtin_offsetof(struct statx, stx_nlink) == 0x10, "stx_nlink offset");
_Static_assert(__builtin_offsetof(struct statx, stx_ino) == 0x20, "stx_ino offset");
_Static_assert(__builtin_offsetof(struct statx, stx_size) == 0x28, "stx_size offset");
_Static_assert(__builtin_offsetof(struct statx, stx_dev_major) == 0x88, "stx_dev_major offset");

static struct stat_native st;
static struct statx sx;
static char out[1024];

static long sys6(long n, long a, long b, long c, long d, long e, long f)
{
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;
	register long x3 __asm__("x3") = d;
	register long x4 __asm__("x4") = e;
	register long x5 __asm__("x5") = f;

	__asm__ volatile("svc #0"
			 : "+r"(x0)
			 : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
			 : "memory", "cc");
	return x0;
}

static u32 put(char *dst, u32 pos, const char *s)
{
	while (*s)
		dst[pos++] = *s++;
	return pos;
}

static u32 putnum(char *dst, u32 pos, u64 v)
{
	char tmp[24];
	int n = 0;

	if (!v) {
		dst[pos++] = '0';
		return pos;
	}
	while (v) {
		tmp[n++] = (char)('0' + (u32)(v % 10));
		v /= 10;
	}
	while (n)
		dst[pos++] = tmp[--n];
	return pos;
}

static u32 putnum_s(char *dst, u32 pos, s64 v)
{
	if (v < 0) {
		dst[pos++] = '-';
		return putnum(dst, pos, (u64)(-v));
	}
	return putnum(dst, pos, (u64)v);
}

static u32 puthex(char *dst, u32 pos, u64 v)
{
	static const char d[] = "0123456789abcdef";
	char tmp[20];
	int n = 0;

	dst[pos++] = '0';
	dst[pos++] = 'x';
	if (!v) {
		dst[pos++] = '0';
		return pos;
	}
	while (v) {
		tmp[n++] = d[v & 0xf];
		v >>= 4;
	}
	while (n)
		dst[pos++] = tmp[--n];
	return pos;
}

static void emit(u32 pos)
{
	sys6(SYS_write, 1, (long)out, pos, 0, 0, 0);
}

static void show_stat(const char *what, long rc, const struct stat_native *s)
{
	u32 pos = 0;

	pos = put(out, pos, what);
	if (rc < 0) {
		pos = put(out, pos, " rc=");
		pos = putnum_s(out, pos, -rc);
		pos = put(out, pos, " (failed)\n");
		emit(pos);
		return;
	}
	pos = put(out, pos, " rc=0 ino=");
	pos = putnum(out, pos, s->st_ino);
	pos = put(out, pos, " dev=");
	pos = puthex(out, pos, s->st_dev);
	pos = put(out, pos, " nlink=");
	pos = putnum(out, pos, s->st_nlink);
	pos = put(out, pos, " size=");
	pos = putnum_s(out, pos, s->st_size);
	pos = put(out, pos, " blksize=");
	pos = putnum_s(out, pos, s->st_blksize);
	pos = put(out, pos, " blocks=");
	pos = putnum_s(out, pos, s->st_blocks);
	pos = put(out, pos, " mtime=");
	pos = putnum_s(out, pos, s->st_mtime);
	pos = put(out, pos, "\n");
	emit(pos);
}

static void show_statx(long rc, u32 req_mask)
{
	u32 pos = 0;

	if (rc < 0) {
		pos = put(out, pos, "statx     : rc=");
		pos = putnum_s(out, pos, -rc);
		pos = put(out, pos, " (failed)\n");
		emit(pos);
		return;
	}
	pos = put(out, pos, "statx     : rc=0 req=");
	pos = puthex(out, pos, req_mask);
	pos = put(out, pos, " mask=");
	pos = puthex(out, pos, sx.stx_mask);
	pos = put(out, pos, " ino=");
	pos = putnum(out, pos, sx.stx_ino);
	pos = put(out, pos, " dev=");
	pos = putnum(out, pos, sx.stx_dev_major);
	pos = put(out, pos, ":");
	pos = putnum(out, pos, sx.stx_dev_minor);
	pos = put(out, pos, " nlink=");
	pos = putnum(out, pos, sx.stx_nlink);
	pos = put(out, pos, " size=");
	pos = putnum(out, pos, sx.stx_size);
	pos = put(out, pos, " blksize=");
	pos = putnum(out, pos, sx.stx_blksize);
	pos = put(out, pos, " blocks=");
	pos = putnum(out, pos, sx.stx_blocks);
	pos = put(out, pos, " mtime=");
	pos = putnum_s(out, pos, sx.stx_mtime.tv_sec);
	pos = put(out, pos, "\n");
	emit(pos);
}

__asm__(
".text\n"
".global _start\n"
".type _start,%function\n"
"_start:\n"
"	mov	x29, #0\n"
"	ldr	x0, [sp]\n"
"	add	x1, sp, #8\n"
"	bl	stat_main\n"
"	mov	x8, #93\n"
"	svc	#0\n"
);

void stat_main(long argc, char **argv);
void stat_main(long argc, char **argv)
{
	const char *path = "/data/local/tmp/dac_probe/visible";
	u32 req_mask = STATX_BASIC_STATS;
	long fd, rc;
	u32 pos = 0;
	int i;

	if (argc > 1)
		path = argv[1];
	if (argc > 2) {
		/* hex, with or without 0x */
		const char *p = argv[2];

		req_mask = 0;
		if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X'))
			p += 2;
		for (i = 0; p[i]; i++) {
			u32 d;

			if (p[i] >= '0' && p[i] <= '9')
				d = (u32)(p[i] - '0');
			else if (p[i] >= 'a' && p[i] <= 'f')
				d = (u32)(p[i] - 'a') + 10;
			else if (p[i] >= 'A' && p[i] <= 'F')
				d = (u32)(p[i] - 'A') + 10;
			else
				break;
			req_mask = (req_mask << 4) | d;
		}
	}

	/* One CPU, so the values do not depend on which core the process landed on (the spoofing is
	 * per-caller-uid, but the inode numbers printed by a filesystem can differ per mount view). */
	{
		unsigned long mask = 1ul << 7;

		sys6(SYS_sched_setaffinity, 0, (long)sizeof(mask), (long)&mask, 0, 0, 0);
	}

	pos = put(out, pos, "path=");
	pos = put(out, pos, path);
	pos = put(out, pos, "\n");
	emit(pos);

	/* 79: the path-based one, the same syscall `ls -li` and `toybox stat` use. */
	rc = sys6(SYS_newfstatat, AT_FDCWD, (long)path, (long)&st, 0, 0, 0);
	show_stat("newfstatat", rc, &st);

	/* 80: the fd-based one.  Same struct, but the buffer is argument 1 and the kernel reaches it
	 * through vfs_fstat() - a different chain, which is why it needed its own whitelist entry. */
	fd = sys6(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
	if (fd < 0) {
		pos = 0;
		pos = put(out, pos, "open failed rc=");
		pos = putnum_s(out, pos, -fd);
		pos = put(out, pos, "\n");
		emit(pos);
	} else {
		rc = sys6(SYS_fstat, fd, (long)&st, 0, 0, 0, 0);
		show_stat("fstat     ", rc, &st);
		sys6(SYS_close, fd, 0, 0, 0, 0, 0);
	}

	/* 291: struct statx, with the caller's mask.  Run it twice so the buffer's own stx_mask can be
	 * compared between a request that names the basic set and one that names almost nothing - the
	 * mask is part of what a reader trusts. */
	rc = sys6(SYS_statx, AT_FDCWD, (long)path, 0, (long)req_mask, (long)&sx, 0);
	show_statx(rc, req_mask);
	if (req_mask != STATX_BASIC_STATS) {
		rc = sys6(SYS_statx, AT_FDCWD, (long)path, 0, STATX_BASIC_STATS, (long)&sx, 0);
		show_statx(rc, STATX_BASIC_STATS);
	}
}
