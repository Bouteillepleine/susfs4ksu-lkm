// SPDX-License-Identifier: GPL-2.0

typedef unsigned long u64;
typedef long s64;

#define SYS_faccessat   48
#define SYS_fchownat    54
#define SYS_openat      56
#define SYS_close       57
#define SYS_getdents64  61
#define SYS_write       64
#define SYS_newfstatat  79
#define SYS_exit        93
#define SYS_clock_gettime 113
#define SYS_statx       291
#define SYS_sched_setaffinity 122
#define SYS_getpid      172

#define AT_FDCWD      (-100)
#define CLOCK_MONOTONIC 1
#define O_RDONLY       0
#define O_DIRECTORY    0x10000

#define STATX_BASIC_STATS 0x7ff
#define MAX_SAMPLES 300
#define DBUF 4096

static char out[512];
static char statbuf[512] __attribute__((aligned(16)));
static char dbuf[DBUF] __attribute__((aligned(16)));
static long sa[MAX_SAMPLES], sb[MAX_SAMPLES], sd[MAX_SAMPLES];

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

static u64 slen(const char *s)
{
	u64 n = 0;

	while (s[n])
		n++;
	return n;
}

static u64 put(char *dst, u64 pos, const char *s)
{
	while (*s)
		dst[pos++] = *s++;
	return pos;
}

static u64 putnum(char *dst, u64 pos, u64 v)
{
	char tmp[24];
	int n = 0;

	if (!v) {
		dst[pos++] = '0';
		return pos;
	}
	while (v) {
		tmp[n++] = (char)('0' + (v % 10));
		v /= 10;
	}
	while (n)
		dst[pos++] = tmp[--n];
	return pos;
}

static u64 now_ns(void)
{
	long ts[2];

	sys6(SYS_clock_gettime, CLOCK_MONOTONIC, (long)ts, 0, 0, 0, 0);
	return (u64)ts[0] * 1000000000ull + (u64)ts[1];
}

static void report(const char *what, u64 iters, u64 took)
{
	u64 per = iters ? took / iters : 0;
	u64 pos = 0;

	pos = put(out, pos, what);
	pos = put(out, pos, ": iters=");
	pos = putnum(out, pos, iters);
	pos = put(out, pos, " total=");
	pos = putnum(out, pos, took);
	pos = put(out, pos, "ns per=");
	pos = putnum(out, pos, per);
	pos = put(out, pos, "ns\n");
	sys6(SYS_write, 1, (long)out, pos, 0, 0, 0);
}

static u64 parse_num(const char *s)
{
	u64 v = 0;

	while (*s >= '0' && *s <= '9')
		v = v * 10 + (u64)(*s++ - '0');
	return v;
}

static long parse_signed(const char *s)
{
	long v = 0;
	int neg = 0;

	if (*s == '-') {
		neg = 1;
		s++;
	}
	while (*s >= '0' && *s <= '9')
		v = v * 10 + (long)(*s++ - '0');
	return neg ? -v : v;
}

/* ---- timing side channel mode ---- */

static u64 putstr(u64 pos, const char *s)
{
	return put(out, pos, s);
}

static u64 putnum_s(u64 pos, long v)
{
	if (v < 0) {
		out[pos++] = '-';
		return putnum(out, pos, (u64)(-v));
	}
	return putnum(out, pos, (u64)v);
}

static long one_call(int kind, const char *path)
{
	long fd;

	switch (kind) {
	case 1:
		return sys6(SYS_faccessat, AT_FDCWD, (long)path, 0, 0, 0, 0);
	case 2:
		return sys6(SYS_fchownat, AT_FDCWD, (long)path, -1, -1, 0, 0);
	case 3:
		return sys6(SYS_newfstatat, AT_FDCWD, (long)path, (long)statbuf, 0, 0, 0);
	case 4:
		return sys6(SYS_statx, AT_FDCWD, (long)path, 0, STATX_BASIC_STATS,
			    (long)statbuf, 0);
	case 5:
		fd = sys6(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);
		if (fd >= 0)
			sys6(SYS_close, fd, 0, 0, 0, 0, 0);
		return fd;
	case 6:

		fd = sys6(SYS_openat, AT_FDCWD, (long)path, O_RDONLY | O_DIRECTORY, 0, 0, 0);
		if (fd < 0)
			return fd;
		sys6(SYS_getdents64, fd, (long)dbuf, DBUF, 0, 0, 0);
		sys6(SYS_close, fd, 0, 0, 0, 0, 0);
		return 0;
	}
	return -1;
}

static u64 put_kind(u64 pos, int kind)
{
	if (kind == 1)
		return putstr(pos, "faccessat");
	if (kind == 2)
		return putstr(pos, "fchownat");
	if (kind == 3)
		return putstr(pos, "newfstatat");
	if (kind == 4)
		return putstr(pos, "statx");
	if (kind == 5)
		return putstr(pos, "openat+close");
	if (kind == 6)
		return putstr(pos, "getdents64(dir)");
	return putstr(pos, "?");
}

static void isort(long *a, int n)
{
	int i, j;

	for (i = 1; i < n; i++) {
		long v = a[i];

		for (j = i - 1; j >= 0 && a[j] > v; j--)
			a[j + 1] = a[j];
		a[j + 1] = v;
	}
}

static long pct(const long *sorted, int n, int p)
{
	int idx = (n * p) / 100;

	if (idx >= n)
		idx = n - 1;
	return sorted[idx];
}

static void paired(int kind, u64 k, int n, const char *pa, const char *pb)
{
	int i, j;
	u64 t0, t1;
	long rca = 0, rcb = 0;
	u64 pos;

	for (i = 0; i < n; i++) {
		t0 = now_ns();
		for (j = 0; j < (int)k; j++)
			rca = one_call(kind, pa);
		t1 = now_ns();
		sa[i] = (long)((t1 - t0) / k);

		t0 = now_ns();
		for (j = 0; j < (int)k; j++)
			rcb = one_call(kind, pb);
		t1 = now_ns();
		sb[i] = (long)((t1 - t0) / k);
		sd[i] = sb[i] - sa[i];
	}

	isort(sa, n);
	isort(sb, n);

	{
		long dmin = sd[0], dmax = sd[0];

		for (i = 1; i < n; i++) {
			if (sd[i] < dmin)
				dmin = sd[i];
			if (sd[i] > dmax)
				dmax = sd[i];
		}
		isort(sd, n);
		pos = putstr(0, "paired kind=");
		pos = put_kind(pos, kind);
		pos = putstr(pos, " batch=");
		pos = putnum(out, pos, k);
		pos = putstr(pos, " samples=");
		pos = putnum(out, pos, (u64)n);
		pos = putstr(pos, "\n  A=");
		pos = putstr(pos, pa);
		pos = putstr(pos, " rc=");
		pos = putnum_s(pos, rca);
		pos = putstr(pos, " p10=");
		pos = putnum(out, pos, (u64)pct(sa, n, 10));
		pos = putstr(pos, " p50=");
		pos = putnum(out, pos, (u64)pct(sa, n, 50));
		pos = putstr(pos, " p90=");
		pos = putnum(out, pos, (u64)pct(sa, n, 90));
		pos = putstr(pos, "\n  B=");
		pos = putstr(pos, pb);
		pos = putstr(pos, " rc=");
		pos = putnum_s(pos, rcb);
		pos = putstr(pos, " p10=");
		pos = putnum(out, pos, (u64)pct(sb, n, 10));
		pos = putstr(pos, " p50=");
		pos = putnum(out, pos, (u64)pct(sb, n, 50));
		pos = putstr(pos, " p90=");
		pos = putnum(out, pos, (u64)pct(sb, n, 90));
		pos = putstr(pos, "\n  diff B-A: min=");
		pos = putnum_s(pos, dmin);
		pos = putstr(pos, " p10=");
		pos = putnum_s(pos, pct(sd, n, 10));
		pos = putstr(pos, " p50=");
		pos = putnum_s(pos, pct(sd, n, 50));
		pos = putstr(pos, " p90=");
		pos = putnum_s(pos, pct(sd, n, 90));
		pos = putstr(pos, " max=");
		pos = putnum_s(pos, dmax);

		pos = putstr(pos, "  sign(neg=");
		{
			int neg = 0;

			for (i = 0; i < n; i++)
				if (sd[i] < 0)
					neg++;
			pos = putnum(out, pos, (u64)neg);
			pos = putstr(pos, "/");
			pos = putnum(out, pos, (u64)n);
			pos = putstr(pos, ") best_threshold_accuracy=");
			pos = putnum(out, pos, (u64)(neg * 100 / n));
			pos = putstr(pos, "%");
			pos = putstr(pos, (neg == n || neg == 0) ? " (perfect)" : "");
		}
		pos = putstr(pos, "\n");
		sys6(SYS_write, 1, (long)out, pos, 0, 0, 0);
	}
}

/* Same entry stub susfs_sc uses: sp points at argc, then argv[0..]. */
__asm__(
".text\n"
".global _start\n"
".type _start,%function\n"
"_start:\n"
"	mov	x29, #0\n"
"	ldr	x0, [sp]\n"
"	add	x1, sp, #8\n"
"	bl	bench_main\n"
"	mov	x8, #93\n"
"	svc	#0\n"
);

void bench_main(long argc, char **argv);

void bench_main(long argc, char **argv)
{
	const char *path = "/data/local/tmp/dac_probe/visible";
	u64 iters = 500000;
	u64 i, r, t0, t1, took, best, best_getpid;
	long rc = 0;

	if (argc > 1)
		path = argv[1];
	if (argc > 2)
		iters = parse_num(argv[2]);

	{
		unsigned long mask = 1ul << 7;

		sys6(SYS_sched_setaffinity, 0, (long)sizeof(mask), (long)&mask, 0, 0, 0);
	}

	/* Timing side channel mode: -p <kind> <batch> <samples> <pathA> <pathB>. */
	if (argc > 1 && argv[1][0] == '-' && argv[1][1] == 'p' && argc >= 7) {
		long kind = parse_signed(argv[2]);
		u64 batch = parse_num(argv[3]);
		long samples = parse_signed(argv[4]);

		if (batch < 1)
			batch = 1;
		if (samples < 2)
			samples = 2;
		if (samples > MAX_SAMPLES)
			samples = MAX_SAMPLES;
		paired((int)kind, batch, (int)samples, argv[5], argv[6]);
		return;
	}

	for (i = 0; i < 1000; i++)
		sys6(SYS_newfstatat, AT_FDCWD, (long)path, (long)statbuf, 0, 0, 0);

#define ROUNDS 10

	best_getpid = ~0ull;
	for (r = 0; r < ROUNDS; r++) {
		t0 = now_ns();
		for (i = 0; i < iters; i++)
			rc += sys6(SYS_getpid, 0, 0, 0, 0, 0, 0);
		took = now_ns() - t0;
		if (took < best_getpid)
			best_getpid = took;
	}	

	best = ~0ull;
	for (r = 0; r < ROUNDS; r++) {
		t0 = now_ns();
		for (i = 0; i < iters; i++)
			rc += sys6(SYS_faccessat, AT_FDCWD, (long)path, 0, 0, 0, 0);
		took = now_ns() - t0;
		if (took < best)
			best = took;
	}
	report("getpid (no hook)", iters, best_getpid);
	report("faccessat", iters, best);

	best = ~0ull;
	for (r = 0; r < ROUNDS; r++) {
		t0 = now_ns();
		for (i = 0; i < iters; i++)
			rc += sys6(SYS_newfstatat, AT_FDCWD, (long)path, (long)statbuf, 0, 0, 0);
		took = now_ns() - t0;
		if (took < best)
			best = took;
	}
	report("newfstatat", iters, best);

	best = ~0ull;
	for (r = 0; r < ROUNDS; r++) {
		t0 = now_ns();
		for (i = 0; i < iters; i++)
			rc += sys6(SYS_statx, AT_FDCWD, (long)path, 0, STATX_BASIC_STATS,
				   (long)statbuf, 0);
		took = now_ns() - t0;
		if (took < best)
			best = took;
	}
	report("statx", iters, best);

	best = ~0ull;
	for (r = 0; r < ROUNDS; r++) {
		t0 = now_ns();
		for (i = 0; i < iters; i++) {
			long fd = sys6(SYS_openat, AT_FDCWD, (long)path, O_RDONLY, 0, 0, 0);

			if (fd >= 0)
				sys6(SYS_close, fd, 0, 0, 0, 0, 0);
		}
		took = now_ns() - t0;
		if (took < best)
			best = took;
	}
	report("openat+close", iters, best);

	if (rc == 0x7fffffff)
		sys6(SYS_write, 1, (long)"unexpected\n", 11, 0, 0, 0);
}
