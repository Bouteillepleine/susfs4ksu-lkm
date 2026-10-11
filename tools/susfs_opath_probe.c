// SPDX-License-Identifier: GPL-2.0
/*
 * susfs_opath_probe - a real-device client for the O_PATH layer
 * (kernel/susfs_opath.c: sys_call_table[56] / [437] and
 * compat_sys_call_table[5] / [322] / [437]).
 *
 * Why this file exists
 * --------------------
 * The layer's contract is that an open(path, O_PATH) on a sus_path-hidden file answers
 * -ENOENT instead of handing out a descriptor.  Nothing in tools/ ever passed O_PATH
 * (`git grep O_PATH tools/` had no match), so that contract had no deterministic
 * client: ls(1), toybox stat and even susfs_stat.c / susfs_compat_stat.c open with
 * flags 0, which is a DIFFERENT path through the layer (the wrappers decide from the
 * file the kernel produced - see "Why f_mode and not the flags" in susfs_opath.c), so a
 * run of those tools cannot say anything about this layer.  This is that client: one
 * source built twice (see "the two ABIs" below), no libc, no allocation, one line of
 * output per method so a shell script or a CI log reads the RUN itself and not only its
 * exit code.
 *
 * The exit code is INVERTED on purpose: 1 means the layer works
 * ------------------------------------------------------------
 * Anyone who assumes 0 = ok reads every result backwards, so this is stated first:
 *
 *     exit 0  - at least one method handed out a descriptor.  On a path a rule HIDES
 *               that is the leak this layer exists to prevent, i.e. the FAILING
 *               outcome, which is what makes `probe <hidden>` usable as a verdict.
 *               There is a second, intended way to reach 0: the CONTROL run against a
 *               path no rule hides, where every method must succeed.  The probe cannot
 *               tell those two apart - it does not know which paths the device's rule
 *               table hides - so the caller owns that distinction: `probe <hidden> ||
 *               echo hidden` and `probe <visible> && echo control-ok` are two different
 *               tests that share one exit code.  That is why every method also prints
 *               its own line: the lines say WHO answered what, and the code says only
 *               whether anything came back at all.
 *     exit 1  - every method answered -ENOENT: the file is gone from all of them.  On a
 *               hidden path this is the PASSING outcome.
 *     exit 2  - usage error.  Nothing was tested, so this is neither outcome, and a
 *               script that folds it into "not 1" would report a leak that never
 *               happened.
 *     exit 3  - no descriptor, but at least one method failed with an errno that is not
 *               ENOENT (ENOSYS on a kernel without openat2, EACCES, EFAULT, ...).  Such a
 *               method was NOT answered the way this layer answers, so it proves nothing
 *               either way: inconclusive by construction, reported as its own code rather
 *               than folded into 1 ("works") or 0 ("leaks").
 *
 * WHICH CALLER runs the probe is part of the question, not part of the harness: the answer this
 * layer gives depends on the calling process (sus_path.c sus_path_gate_ok() - the caller has to be
 * an umounted app and must not own the file), so a root shell is NOT gated and legitimately keeps a
 * descriptor for a path a rule hides.  Run it from the context whose answer is being asked - this
 * project's app-side device recipe is `su 10000 -c ...` - and read a root run as the CONTROL, where
 * exit 0 is the expected answer rather than a leak.  The banner line says where the probe stands;
 * the uid gate's answer is the kernel's.
 *
 * Why a successful fd is PROVED with /proc/self/fd/N
 * --------------------------------------------------
 * An O_PATH descriptor holds no data: open() with O_PATH sets f_mode = FMODE_PATH and
 * f_op = &empty_fops in do_dentry_open() and returns BEFORE security_file_open(), so
 * read() on it fails by definition and the leak is not "the content became readable".
 * The leak is that a usable descriptor exists at all, and that is what a detector buys
 * with it - fstatat(fd, "", AT_EMPTY_PATH) reads the hidden file's inode and metadata,
 * and the fd works as the dirfd of an *at() call.  None of that can be read out of the
 * descriptor with read(), so it is read out of what the descriptor RESOLVES to:
 * readlink("/proc/self/fd/N") is answered by the kernel from the file the fd actually
 * holds (f_path), so it NAMES the hidden file even though nothing else on the system
 * will - which is precisely the finding that makes this layer worth testing, and the one
 * thing the stat family cannot show.  readlinkat(AT_FDCWD, ...) is used rather than
 * readlink() because arm64 has no readlink(2) at all (only the *at() form), so one call
 * shape covers both ABIs.
 * The fd is closed immediately afterwards, so the methods all start from the same state:
 * a descriptor left open would be a second difference between the runs, on top of the one
 * being measured.
 *
 * the two ABIs
 * ------------
 * One source, two syscall ABIs, selected by the compiler's own predefined macros - the
 * same split susfs_stat.c (aarch64) and susfs_compat_stat.c (armv7a) already carry, and
 * for the same reason: a 64-bit process CANNOT make a 32-bit syscall, so
 * compat_sys_call_table is unreachable from an aarch64 client and sys_call_table[56]/
 * [437] are unreachable from a 32-bit one.  No single binary covers both, which is why
 * this file is compiled twice and why both artifacts have to end up on the device.
 *
 * Numeral sources, so the next reader does not have to guess:
 *   native (aarch64, include/uapi/asm-generic/unistd.h):
 *     openat 56 (:183)   openat2 437 (:854)   close 57 (:185)
 *     write 64 (:207)    readlinkat 78 (:247)  exit 93 (:306)
 *     `open` - DOES NOT EXIST.  asm-generic defines no __NR_open at all: the only
 *     path-taking entries are openat and openat2.  So the native build offers no `open`
 *     method, and asking for one is a USAGE ERROR (exit 2) rather than a silent skip: a
 *     method a script believes it ran, but which was quietly dropped, is how a gap in
 *     the evidence reads as coverage.
 *   compat (armv7a; arch/arm/tools/syscall.tbl, which is what
 *   arch/arm64/include/asm/unistd32.h is generated from):
 *     open 5 (:19)   close 6 (:20)   write 4 (:18)   exit 1 (:15)
 *     openat 322 (:339)   readlinkat 332 (:349)   openat2 437 (:453)
 *     - `open` is not just a different number from openat, it is a different SIGNATURE:
 *       `5 common open sys_open` takes (path, flags, mode) and has NO DIRFD, so the call
 *       below passes three arguments where openat passes four.  The arm64 compat table
 *       maps 5 to compat_sys_open (unistd32.h:23-24) - that wrapper exists for the
 *       AArch32 flag space, not to add a dirfd.
 *     - openat2 is 437 in BOTH ABIs, but they are different table entries pointing at the
 *       same function: unistd32.h:884-885 registers the AArch32 slot as
 *       `__SYSCALL(__NR_openat2, sys_openat2)`, i.e. the NATIVE implementation, and
 *       arch/arm64/kernel/sys32.c turns that into compat_sys_call_table[437] =
 *       __arm64_sys_openat2.  That is why susfs_opath.c needs a separate nr_compat entry
 *       and a separate wrapper for it, and why this probe has to ask for the same number
 *       from a 32-bit caller to reach the compat slot at all.
 *     - O_PATH is the SAME value in both ABIs, 010000000 (0x200000),
 *       include/uapi/asm-generic/fcntl.h:85 - which is what makes the two runs
 *       comparable.  O_NOFOLLOW is NOT: arch/arm/include/uapi/asm/fcntl.h:6 overrides it
 *       to 0100000 (0x8000) while asm-generic/fcntl.h:57 has 00400000 (0x20000).  The two
 *       numbers select different flags on the two ABIs, so --nofollow builds the value per
 *       ABI instead of hardcoding one.
 *
 * Build (see the tools job in .github/workflows/build-ddk.yml, which builds both):
 *
 *     clang --target=aarch64-linux-gnu -O2 -nostdlib -static-pie \
 *           -fno-stack-protector -fno-builtin -fuse-ld=lld -Wl,-e,_start \
 *           -o /tmp/susfs_opath_probe tools/susfs_opath_probe.c
 *     clang --target=armv7a-linux-androideabi -march=armv7-a -O2 -nostdlib \
 *           -static-pie -fno-stack-protector -fno-builtin -fuse-ld=lld \
 *           -Wl,-e,_start -o /tmp/susfs_opath_probe_compat tools/susfs_opath_probe.c
 *
 * Usage: susfs_opath_probe <path> [open] [openat] [openat2] [--nofollow]
 *   No method named = every method this ABI has; the flags are always O_PATH, plus
 *   O_NOFOLLOW with --nofollow.  An O_PATH|O_NOFOLLOW open of a symlink keeps the symlink
 *   itself while a plain O_PATH open follows it and hands the layer the TARGET's inode -
 *   two different questions about a hidden path, so both are reachable.
 *   The path must be one a sus_path rule hides for exit 1 to mean "the layer works"; see
 *   the exit-code table above for what the control run on a visible path answers.
 */

typedef unsigned long long u64;
typedef unsigned int u32;

/* ------------------------------------------------------------------ the two ABIs */

#if defined(__aarch64__)
#define PROBE_NATIVE 1
#define SYS_write 64
#define SYS_close 57
#define SYS_readlinkat 78
#define SYS_openat 56
#define SYS_openat2 437
/* asm-generic/fcntl.h:57 */
#define O_NOFOLLOW 00400000
#elif defined(__arm__) || defined(__thumb__)
#define PROBE_NATIVE 0
#define SYS_write 4
#define SYS_close 6
#define SYS_readlinkat 332
#define SYS_open 5		/* (path, flags, mode) - no dirfd, see the header */
#define SYS_openat 322
#define SYS_openat2 437
/* arch/arm/include/uapi/asm/fcntl.h:6 overrides the asm-generic value */
#define O_NOFOLLOW 0100000
#else
#error "build this probe for aarch64-linux-gnu (native) or armv7a-linux-androideabi (32-bit)"
#endif

#define AT_FDCWD (-100)
/* The same in both ABIs: include/uapi/asm-generic/fcntl.h:85. */
#define O_PATH 010000000

/* The method bits, so `want` is one word and the three call sites cannot drift from the
 * usage text. */
#define M_OPEN 1u
#define M_OPENAT 2u
#define M_OPENAT2 4u

/* include/uapi/linux/openat2.h: struct open_how { __u64 flags; __u64 mode;
 * __u64 resolve; }.  Three u64, so sizeof is 24 whatever the compiler's alignment for
 * u64 is, and 24 is what `size` must carry: openat2() rejects a size BELOW sizeof with
 * -EINVAL and accepts a larger one only while the extra bytes are zero, so a wrong size
 * here would read as "the layer did not answer" when nothing was ever asked. */
struct open_how {
	u64 flags;
	u64 mode;
	u64 resolve;
};

_Static_assert(sizeof(struct open_how) == 24, "open_how size");

/* ------------------------------------------------------------------ the syscall ABI */

#if PROBE_NATIVE
/* aarch64: nr in x8, args in x0..x5 - the same wrapper susfs_stat.c uses. */
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
#else
/* armv7a: nr in r7, args in r0..r3 - the same wrapper susfs_compat_stat.c uses.  A 32-bit
 * task never passes a 5th argument, and every call below needs at most four. */
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
#endif

/* One call shape - (nr, a, b, c, d) - for both builds, so the call sites and the argument
 * ORDER they encode cannot differ between the two ABIs; the native one fills the unused
 * 5th register with 0 exactly the way susfs_stat.c does. */
#if PROBE_NATIVE
static long sc(long n, long a, long b, long c, long d)
{
	return sys6(n, a, b, c, d, 0, 0);
}
#else
static long sc(long n, long a, long b, long c, long d)
{
	return sys4(n, a, b, c, d);
}
#endif

/* ------------------------------------------------------------------ output helpers */

/* A PATH_MAX path is printed twice on a success line (once as the argument, once as what
 * /proc/self/fd resolved to) and there is no libc here to catch an overrun, so the writers
 * below stop at the end of the buffer instead of trusting the input.  Truncation is the
 * worst case, never a wild write. */
#define OUTSZ 8192

static char out[OUTSZ];
/* readlinkat() returns a LENGTH and does not terminate, so the target is kept as bytes
 * plus a count (putn below) instead of as a string. */
static char target[4096];
static struct open_how how;

static u32 put(char *dst, u32 pos, const char *s)
{
	while (*s && pos < OUTSZ - 1)
		dst[pos++] = *s++;
	return pos;
}

static u32 putn(char *dst, u32 pos, const char *s, u32 n)
{
	u32 i;

	for (i = 0; i < n && pos < OUTSZ - 1; i++)
		dst[pos++] = s[i];
	return pos;
}

/* armv7a has no 64-bit division instruction and a freestanding link has no libgcc: a
 * `v / 10` in the 32-bit build pulls in __aeabi_uldivmod and FAILS TO LINK (measured -
 * see the note in susfs_compat_stat.c, whose first version hit exactly that).  Rather than
 * format the 64-bit build's numbers one way and the 32-bit build's another, both go
 * through this shift-subtract division: the counts printed here are tiny, and one
 * implementation cannot report a number the other build cannot. */
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

static u32 putnum(char *dst, u32 pos, u64 v)
{
	char tmp[24];
	int n = 0;

	if (!v)
		return put(dst, pos, "0");
	while (v) {
		u64 rem;

		v = u64_div10(v, &rem);
		tmp[n++] = (char)('0' + (u32)rem);
	}
	while (n && pos < OUTSZ - 1)
		dst[pos++] = tmp[--n];
	return pos;
}

/* The flags are printed in hex because 0x200000 IS the claim "O_PATH was asked for": a
 * probe that opened with flags 0 would exercise a different table entry and prove nothing
 * about this layer, and a bare decimal cannot be checked against the header. */
static u32 puthex(char *dst, u32 pos, u64 v)
{
	static const char d[] = "0123456789abcdef";
	char tmp[20];
	int n = 0;

	if (pos + 18 > OUTSZ)		/* "0x" + at most 16 digits */
		return pos;
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

/* fd 2 for the usage text, fd 1 for the readings: a script collecting stdout for the
 * per-method lines gets no prose mixed into its data. */
static void emit(long fd, u32 pos)
{
	sc(SYS_write, fd, (long)out, (long)pos, 0);
}

/* The errno names a caller of THIS layer actually sees.  A number alone is not enough to
 * tell "the layer answered" from "the kernel refused", and those two look identical in a
 * log that prints only the number. */
static const char *errno_name(long e)
{
	switch (e) {
	case 1:  return "EPERM";
	case 2:  return "ENOENT";
	case 9:  return "EBADF";
	case 13: return "EACCES";
	case 14: return "EFAULT";
	case 20: return "ENOTDIR";
	case 22: return "EINVAL";
	case 36: return "ENAMETOOLONG";
	case 38: return "ENOSYS";
	case 40: return "ELOOP";
	case 95: return "EOPNOTSUPP";
	default: return 0;
	}
}

/* ------------------------------------------------------------------ run accounting */

static int n_attempted;
static int n_enoent;
static int n_leak;
static int n_other;

/* "/proc/self/fd/<n>", built by hand: no libc, and no `%` on the 32-bit build either (see
 * u64_div10).  32 bytes is the 14-character directory + a 64-bit fd's digits + NUL. */
static void fd_link(char *dst, long fd)
{
	static const char dir[] = "/proc/self/fd/";
	char tmp[24];
	u64 v = (u64)fd;
	u32 pos = 0;
	int i = 0, n = 0;

	while (dir[i])
		dst[pos++] = dir[i++];
	if (!v) {
		/* Never 0/1/2 in practice - O_PATH does not hand out the stdio
		 * descriptors - but printing nothing for 0 would be a trap. */
		dst[pos++] = '0';
	} else {
		while (v) {
			u64 rem;

			v = u64_div10(v, &rem);
			tmp[n++] = (char)('0' + (u32)rem);
		}
		while (n)
			dst[pos++] = tmp[--n];
	}
	dst[pos] = 0;
}

/* The second line of a success: what the descriptor actually holds.  This is the evidence
 * the first line cannot carry - see "Why a successful fd is PROVED" in the file header. */
static void show_fd(const char *method, long fd)
{
	char link[32];
	const char *nm;
	u32 pos = 0;
	long n, rc;

	fd_link(link, fd);
	n = sc(SYS_readlinkat, AT_FDCWD, (long)link, (long)target,
	       (long)sizeof(target));

	pos = put(out, pos, method);
	pos = put(out, pos, " fd=");
	pos = putnum(out, pos, (u64)fd);
	pos = put(out, pos, " ");
	pos = put(out, pos, link);
	pos = put(out, pos, " -> ");
	if (n < 0) {
		/* Cannot happen for a descriptor the kernel just handed out, and printed
		 * rather than assumed: an unreadable /proc (hidepid=2, an SELinux denial,
		 * a pid namespace with no procfs of its own) would otherwise collapse into
		 * a silent "no target", which reads like an fd that points nowhere. */
		pos = put(out, pos, "readlinkat failed errno=");
		pos = putnum(out, pos, (u64)(-n));
		nm = errno_name(-n);
		if (nm) {
			pos = put(out, pos, " ");
			pos = put(out, pos, nm);
		}
	} else {
		/* Quoted, and with the byte count: the string is the kernel's answer, not
		 * ours, and a target exactly as long as the buffer would be
		 * indistinguishable from a longer one without the count. */
		pos = put(out, pos, "\"");
		pos = putn(out, pos, target, (u32)n);
		pos = put(out, pos, "\" (");
		pos = putnum(out, pos, (u64)n);
		pos = put(out, pos, " bytes)");
	}
	pos = put(out, pos, "\n");
	emit(1, pos);

	/* Closed before the next method runs, so the runs differ in the syscall under test
	 * and in nothing else. */
	rc = sc(SYS_close, fd, 0, 0, 0);
	if (rc < 0) {
		pos = 0;
		pos = put(out, pos, method);
		pos = put(out, pos, " fd=");
		pos = putnum(out, pos, (u64)fd);
		pos = put(out, pos, " close failed errno=");
		pos = putnum(out, pos, (u64)(-rc));
		pos = put(out, pos, "\n");
		emit(1, pos);
	}
}

/* One line per method - the format the header documents - plus the fd proof on success.
 * Every method is counted the same way here, so a method the usage error keeps from
 * running cannot end up in the totals. */
static void report(const char *method, const char *path, long rc)
{
	const char *nm;
	u32 pos = 0;

	n_attempted++;
	pos = put(out, pos, method);
	pos = put(out, pos, " ");
	pos = put(out, pos, path);
	pos = put(out, pos, " -> fd=");
	if (rc < 0) {
		/* A raw syscall returns -errno and there is no errno variable here; the
		 * conventional fd=-1 is printed alongside it so the line reads the way it
		 * would from a libc caller. */
		pos = put(out, pos, "-1 errno=");
		pos = putnum(out, pos, (u64)(-rc));
		nm = errno_name(-rc);
		if (nm) {
			pos = put(out, pos, " ");
			pos = put(out, pos, nm);
		}
		pos = put(out, pos, "\n");
		emit(1, pos);
		if (rc == -2)
			n_enoent++;
		else
			n_other++;
		return;
	}

	n_leak++;
	pos = putnum(out, pos, (u64)rc);
	pos = put(out, pos, " errno=0\n");
	emit(1, pos);
	show_fd(method, rc);
}

/* ------------------------------------------------------------------ usage */

static void usage(int which)
{
	u32 pos = 0;

	if (which) {
		pos = put(out, pos, "usage error: ");
		switch (which) {
		case 1:
			pos = put(out, pos, "no path given");
			break;
		case 2:
			pos = put(out, pos, "unknown argument");
			break;
		default:
#if PROBE_NATIVE
			pos = put(out, pos, "`open` is not a syscall on arm64 (asm-generic has no "
					    "__NR_open; only openat 56 and openat2 437) - this is "
					    "the aarch64 build, use the armv7a one for the AArch32 "
					    "open(5)");
#else
			pos = put(out, pos, "unreachable");
#endif
			break;
		}
		pos = put(out, pos, "\n");
		emit(2, pos);
	}

	pos = 0;
	pos = put(out, pos, "usage: susfs_opath_probe <path> [open] [openat] [openat2] [--nofollow]\n");
	pos = put(out, pos, "  no method named = every method this ABI has; flags are O_PATH, plus\n");
	pos = put(out, pos, "  O_NOFOLLOW with --nofollow.  One line per method:\n");
	pos = put(out, pos, "    METHOD <path> -> fd=<n> errno=<E> [NAME]\n");
	pos = put(out, pos, "  and, when a descriptor came back, a second line with what it resolves\n");
	pos = put(out, pos, "  to (readlinkat of /proc/self/fd/<n>).\n");
	pos = put(out, pos, "  exit 0 = a descriptor came back (LEAK on a hidden path, and the expected\n");
	pos = put(out, pos, "           answer of the control run on a visible one)\n");
	pos = put(out, pos, "  exit 1 = every method answered ENOENT (the layer works)\n");
	pos = put(out, pos, "  exit 2 = usage error; exit 3 = inconclusive (see the file header)\n");
#if PROBE_NATIVE
	pos = put(out, pos, "  this is the aarch64 build: arm64 has no open() at all, only openat(56)\n");
	pos = put(out, pos, "  and openat2(437); the AArch32 open/openat/openat2 (5/322/437) entries need\n");
	pos = put(out, pos, "  the armv7a build of this same source.\n");
#endif
	emit(2, pos);
}

/* ------------------------------------------------------------------ entry point */

__asm__(
".text\n"
".global _start\n"
".type _start,%function\n"
"_start:\n"
#if PROBE_NATIVE
/* Unlike susfs_stat.c and susfs_compat_stat.c, which exit 0 unconditionally, this probe
 * EXITS WITH MAIN'S RETURN VALUE: the exit code is half of its output (see the header).
 * x0 arrives at the svc untouched from the `bl`, which is where the callee left it. */
"	mov	x29, #0\n"
"	ldr	x0, [sp]\n"
"	add	x1, sp, #8\n"
"	bl	opath_main\n"
"	mov	x8, #93\n"
"	svc	#0\n"
#else
"	mov	fp, #0\n"
"	ldr	r0, [sp]\n"
"	add	r1, sp, #4\n"
"	bl	opath_main\n"
"	mov	r7, #1\n"
"	svc	#0\n"
#endif
);

long opath_main(long argc, char **argv);
long opath_main(long argc, char **argv)
{
	const char *path;
	unsigned long flags = O_PATH;
	unsigned int want = 0;
	long rc;
	int code;
	u32 pos;
	int i, sep;

	if (argc < 2) {
		usage(1);
		return 2;
	}
	path = argv[1];

	for (i = 2; i < argc; i++) {
		const char *a = argv[i];

		if (a[0] == '-' && a[1] == '-') {
			/* "--nofollow", compared literally: this file links no strcmp. */
			if (a[2] == 'n' && a[3] == 'o' && a[4] == 'f' && a[5] == 'o' &&
			    a[6] == 'l' && a[7] == 'l' && a[8] == 'o' && a[9] == 'w' &&
			    a[10] == 0) {
				flags |= O_NOFOLLOW;
				continue;
			}
			pos = 0;
			pos = put(out, pos, "usage error: unknown option ");
			pos = put(out, pos, a);
			pos = put(out, pos, "\n");
			emit(2, pos);
			usage(0);
			return 2;
		}
		if (a[0] == 'o' && a[1] == 'p' && a[2] == 'e' && a[3] == 'n' && a[4] == 0) {
			want |= M_OPEN;
			continue;
		}
		if (a[0] == 'o' && a[1] == 'p' && a[2] == 'e' && a[3] == 'n' &&
		    a[4] == 'a' && a[5] == 't' && a[6] == 0) {
			want |= M_OPENAT;
			continue;
		}
		if (a[0] == 'o' && a[1] == 'p' && a[2] == 'e' && a[3] == 'n' &&
		    a[4] == 'a' && a[5] == 't' && a[6] == '2' && a[7] == 0) {
			want |= M_OPENAT2;
			continue;
		}
		pos = 0;
		pos = put(out, pos, "usage error: unknown argument ");
		pos = put(out, pos, a);
		pos = put(out, pos, "\n");
		emit(2, pos);
		usage(0);
		return 2;
	}

	if (!want) {
		want = M_OPENAT | M_OPENAT2;
#if !PROBE_NATIVE
		want |= M_OPEN;
#endif
	}

#if PROBE_NATIVE
	/* Not a skip: a caller that asked for `open` on the aarch64 build would otherwise
	 * believe three entries were tested and hear from two. */
	if (want & M_OPEN) {
		usage(3);
		return 2;
	}
#endif

	/* The banner records what was run, because the exit code alone does not: which ABI,
	 * which flags - the value that makes this an O_PATH open at all - and which
	 * methods. */
	pos = 0;
	pos = put(out, pos, "abi=");
	pos = put(out, pos, PROBE_NATIVE ? "aarch64" : "armv7a(32-bit)");
	pos = put(out, pos, " path=");
	pos = put(out, pos, path);
	pos = put(out, pos, " flags=");
	pos = puthex(out, pos, (u64)flags);
	pos = put(out, pos, " (O_PATH");
	if (flags & O_NOFOLLOW)
		pos = put(out, pos, "|O_NOFOLLOW");
	pos = put(out, pos, ") methods=");
	sep = 0;
	if (want & M_OPEN) {
		if (sep++)
			pos = put(out, pos, " ");
		pos = put(out, pos, "open");
	}
	if (want & M_OPENAT) {
		if (sep++)
			pos = put(out, pos, " ");
		pos = put(out, pos, "openat");
	}
	if (want & M_OPENAT2) {
		if (sep++)
			pos = put(out, pos, " ");
		pos = put(out, pos, "openat2");
	}
	pos = put(out, pos, "\n");
	emit(1, pos);

#if !PROBE_NATIVE
	if (want & M_OPEN) {
		/* (path, flags, mode): three arguments, no dirfd.  See the header - this is
		 * the ABI difference that a copy of the openat call cannot express. */
		rc = sc(SYS_open, (long)path, (long)flags, 0, 0);
		report("open", path, rc);
	}
#endif

	if (want & M_OPENAT) {
		/* The mode register is read only for O_CREAT/O_TMPFILE and O_PATH is
		 * neither, so 0 is what the kernel expects here. */
		rc = sc(SYS_openat, AT_FDCWD, (long)path, (long)flags, 0);
		report("openat", path, rc);
	}

	if (want & M_OPENAT2) {
		how.flags = (u64)flags;
		how.mode = 0;
		/* resolve=0: no RESOLVE_* restriction.  A non-zero resolve field changes the
		 * LOOKUP itself, and the point of this run is that the layer is the only
		 * thing changing the answer. */
		how.resolve = 0;
		rc = sc(SYS_openat2, AT_FDCWD, (long)path, (long)&how, (long)sizeof(how));
		report("openat2", path, rc);
	}

	pos = 0;
	pos = put(out, pos, "result: attempted=");
	pos = putnum(out, pos, (u64)n_attempted);
	pos = put(out, pos, " enoent=");
	pos = putnum(out, pos, (u64)n_enoent);
	pos = put(out, pos, " leak=");
	pos = putnum(out, pos, (u64)n_leak);
	pos = put(out, pos, " other=");
	pos = putnum(out, pos, (u64)n_other);
	pos = put(out, pos, " -> exit ");
	if (n_leak) {
		code = 0;
		pos = putnum(out, pos, 0);
		pos = put(out, pos, " (a descriptor came back: LEAK if this path is hidden)\n");
	} else if (n_other) {
		code = 3;
		pos = putnum(out, pos, 3);
		pos = put(out, pos, " (inconclusive: a method failed with something other than ENOENT)\n");
	} else {
		code = 1;
		pos = putnum(out, pos, 1);
		pos = put(out, pos, " (hidden: every method answered ENOENT)\n");
	}
	emit(1, pos);

	return code;
}
