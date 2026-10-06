// SPDX-License-Identifier: GPL-2.0

typedef unsigned long long u64;
typedef long long s64;
typedef unsigned int u32;

#define SYS_exit 1
#define SYS_write 4
#define SYS_open 5
#define SYS_lseek 19
#define __NR_fstatat64 327
#define __NR_fstat64 197
#define __NR_stat64 195
#define __NR_lstat64 196
#define AT_FDCWD (-100)

struct stat64_compat {
	u64 st_dev;			/* 0  */
	unsigned char __pad0[4];	/* 8  */
	u32 __st_ino;			/* 12 (filled by the kernel) */
	u32 st_mode;			/* 16 */
	u32 st_nlink;			/* 20 */
	u32 st_uid;			/* 24 */
	u32 st_gid;			/* 28 */
	u64 st_rdev;			/* 32 */
	unsigned char __pad3[4];	/* 40 */
	s64 st_size;			/* 48 (8-byte aligned on arm64) */
	u32 st_blksize;			/* 56 */
	u64 st_blocks;			/* 64 */
	u32 st_atime;			/* 72 */
	u32 st_atime_nsec;		/* 76 */
	u32 st_mtime;			/* 80 */
	u32 st_mtime_nsec;		/* 84 */
	u32 st_ctime;			/* 88 */
	u32 st_ctime_nsec;		/* 92 */
	u64 st_ino;			/* 96 (left alone: STAT64_HAS_BROKEN_ST_INO) */
};

_Static_assert(sizeof(struct stat64_compat) == 104, "stat64 size");
_Static_assert(__builtin_offsetof(struct stat64_compat, __st_ino) == 12, "stat64 __st_ino");
_Static_assert(__builtin_offsetof(struct stat64_compat, st_size) == 48, "stat64 st_size");
_Static_assert(__builtin_offsetof(struct stat64_compat, st_blocks) == 64, "stat64 st_blocks");
_Static_assert(__builtin_offsetof(struct stat64_compat, st_ctime_nsec) == 92, "stat64 st_ctime_nsec");
_Static_assert(__builtin_offsetof(struct stat64_compat, st_ino) == 96, "stat64 st_ino");

static struct stat64_compat st;
static char out[512];

static long sys4(long n, long a, long b, long c, long d)
{
	register long r7 __asm__("r7") = n;
	register long r0 __asm__("r0") = a;
	register long r1 __asm__("r1") = b;
	register long r2 __asm__("r2") = c;
	register long r3 __asm__("r3") = d;

	__asm__ volatile("svc #0"
			 : "+r"(r0)
			 : "r"(r7), "r"(r1), "r"(r2), "r"(r3)
			 : "memory", "cc");
	return r0;
}

static u32 put(char *dst, u32 pos, const char *s)
{
	while (*s)
		dst[pos++] = *s++;
	return pos;
}

static u64 u64_div10(u64 v, u64 *rem)
{
	u64 q = 0, r = 0;
	int i;

	for (i = 63; i >= 0; i--) {
		r = (r << 1) | ((v >> i) & 1);
		if (r >= 10) {
			r -= 10;
			q |= (1ull << i);
		}
	}
	*rem = r;
	return q;
}

static u32 putnum(char *dst, u32 pos, u64 v, int neg)
{
	char tmp[24];
	int n = 0;

	if (neg)
		dst[pos++] = '-';
	if (!v) {
		dst[pos++] = '0';
		return pos;
	}
	while (v) {
		u64 rem;

		v = u64_div10(v, &rem);
		tmp[n++] = (char)('0' + (u32)rem);
	}
	while (n)
		dst[pos++] = tmp[--n];
	return pos;
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

static void show(const char *what, long rc)
{
	u32 pos = 0;

	pos = put(out, pos, what);
	if (rc < 0) {
		pos = put(out, pos, " rc=");
		pos = putnum(out, pos, (u64)(-rc), 0);
		pos = put(out, pos, " (failed)\n");
		sys4(SYS_write, 1, (long)out, pos, 0);
		return;
	}
	pos = put(out, pos, " ino=");
	pos = putnum(out, pos, st.st_ino, 0);
	pos = put(out, pos, " broken_ino=");
	pos = putnum(out, pos, st.__st_ino, 0);
	pos = put(out, pos, " dev=");
	pos = puthex(out, pos, st.st_dev);
	pos = put(out, pos, " nlink=");
	pos = putnum(out, pos, st.st_nlink, 0);
	pos = put(out, pos, " size=");
	pos = putnum(out, pos, (u64)st.st_size, 0);
	pos = put(out, pos, " mtime=");
	pos = putnum(out, pos, (u64)st.st_mtime, 0);
	pos = put(out, pos, "\n");
	sys4(SYS_write, 1, (long)out, pos, 0);
}

#define __NR_getdents 141
#define __NR_getdents64 217
#define DIRBUF 4096

static char dirbuf[DIRBUF];

static int name_is(const char *p, const char *needle)
{
	if (!needle || !needle[0])
		return 0;
	while (*needle) {
		if (*p++ != *needle++)
			return 0;
	}
	return *p == 0;
}

static u32 scan_dir(long fd, int compat, const char *needle, u32 *entries)
{
	u32 matches = 0;
	long n;

	*entries = 0;
	while ((n = sys4(compat ? __NR_getdents : __NR_getdents64,
			 fd, (long)dirbuf, DIRBUF, 0)) > 0) {
		long off = 0;

		while (off < n) {
			u32 reclen, nameoff;

			if (off + (compat ? 10 : 18) > n)
				break;

			if (compat) {
				reclen = (unsigned char)dirbuf[off + 8] |
					 ((u32)(unsigned char)dirbuf[off + 9] << 8);
				nameoff = 10;
			} else {
				reclen = (unsigned char)dirbuf[off + 16] |
					 ((u32)(unsigned char)dirbuf[off + 17] << 8);
				nameoff = 19;
			}
			if (reclen < nameoff + 1 || off + (long)reclen > n)
				break;
			(*entries)++;
			if (name_is(dirbuf + off + nameoff, needle))
				matches++;
			off += reclen;
		}
	}
	return matches;
}

static void show_dirents(long dirfd, int compat, const char *needle)
{
	u32 pos = 0, entries = 0;
	u32 matches = scan_dir(dirfd, compat, needle, &entries);

	pos = put(out, pos, compat ? "getdents(141)  " : "getdents64(217)");
	pos = put(out, pos, " entries=");
	pos = putnum(out, pos, entries, 0);
	pos = put(out, pos, " needle_hits=");
	pos = putnum(out, pos, matches, 0);
	pos = put(out, pos, "\n");
	sys4(SYS_write, 1, (long)out, pos, 0);
}

__asm__(
".text\n"
".global _start\n"
".type _start,%function\n"
"_start:\n"
"	mov	fp, #0\n"
"	ldr	r0, [sp]\n"
"	add	r1, sp, #4\n"
"	bl	compat_main\n"
"	mov	r7, #1\n"
"	svc	#0\n"
);

void compat_main(long argc, char **argv);
void compat_main(long argc, char **argv)
{
	const char *path = "/data/local/tmp/dac_probe/visible";
	const char *dir = "/data/local/tmp/dac_probe";
	const char *needle = "open600";
	long fd, rc;
	u32 pos = 0;

	if (argc > 1)
		path = argv[1];
	if (argc > 2)
		dir = argv[2];
	if (argc > 3)
		needle = argv[3];

	pos = put(out, pos, "struct stat64 size=");
	pos = putnum(out, pos, (u64)sizeof(st), 0);
	pos = put(out, pos, " (expect 104; 96 would mean a 4-byte-aligned layout)\n");
	sys4(SYS_write, 1, (long)out, pos, 0);

	rc = sys4(__NR_fstatat64, AT_FDCWD, (long)path, (long)&st, 0);
	show("fstatat64", rc);

	rc = sys4(__NR_stat64, (long)path, (long)&st, 0, 0);
	show("stat64   ", rc);

	rc = sys4(__NR_lstat64, (long)path, (long)&st, 0, 0);
	show("lstat64  ", rc);

	fd = sys4(SYS_open, (long)path, 0, 0, 0);
	if (fd >= 0) {
		rc = sys4(__NR_fstat64, fd, (long)&st, 0, 0);
		show("fstat64  ", rc);
	}

	fd = sys4(SYS_open, (long)dir, 0, 0, 0);
	if (fd < 0) {
		pos = 0;
		pos = put(out, pos, "open(dir) failed\n");
		sys4(SYS_write, 1, (long)out, pos, 0);
		return;
	}
	pos = 0;
	pos = put(out, pos, "dir=");
	pos = put(out, pos, dir);
	pos = put(out, pos, " needle=");
	pos = put(out, pos, needle);
	pos = put(out, pos, "\n");
	sys4(SYS_write, 1, (long)out, pos, 0);
	show_dirents(fd, 0, needle);	/* getdents64 (217) -> native body         */
	sys4(SYS_lseek, fd, 0, 0, 0);	/* rewind between the two interfaces       */
	show_dirents(fd, 1, needle);	/* getdents   (141) -> compat body         */
}
