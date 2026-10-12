/* Host test for plugin/pmon_trace.c, driven by check_pmon_trace.py.
 *
 *   pmon_trace_host IN.csv OUT.pmon [FIRST_FRAME | -LAST_N] [HEAP_CAP]
 *
 * Converts the CSV the way the plugin does (size pass, then sequential 0xF000 reads), writes
 * the result, then re-reads odd-sized, random and backward windows and checks each against the
 * sequential bytes. Prints "bytes=N scenes=N frames=N jobs=N bookmarks=N samples=N late=N
 * dropped=N first=N". Exit 1 if a window differs or the size pass disagrees with the reads. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../plugin/pmon_trace.h"

typedef struct Mem { const char *data; unsigned int len; } Mem;

static int mem_read(void *ctx, unsigned int off, char *buf, unsigned int len)
{
	Mem *m = (Mem *)ctx;

	if (off >= m->len)
		return 0;
	if (len > m->len - off)
		len = m->len - off;
	if (len > 1500)                 /* odd chunk size: lines straddle reads */
		len = 1500;
	memcpy(buf, m->data + off, len);
	return (int)len;
}

static unsigned int rng = 12345;
static unsigned int rnd(unsigned int n)
{
	rng = rng * 1103515245u + 12345u;
	return ((rng >> 8) & 0xFFFFFF) % (n ? n : 1);
}

int main(int argc, char **argv)
{
	static unsigned char stage[PMON_STAGE];
	static PmonEvent heap[PMON_HEAP_EVENTS];
	static PmonLive live[PMON_LIVE_INTERVALS];
	static PmonTrace t;
	char scan[777];
	Mem m;
	FILE *f;
	long sz;
	unsigned char *out;
	unsigned int total, off, first = 0, heap_cap = PMON_HEAP_EVENTS, i, fails = 0;
	const unsigned char *d;

	if (argc < 3)
		return 2;
	f = fopen(argv[1], "rb");
	if (!f)
		return 2;
	fseek(f, 0, SEEK_END);
	sz = ftell(f);
	fseek(f, 0, SEEK_SET);
	m.data = (char *)malloc((size_t)sz + 1);
	m.len = (unsigned int)fread((char *)m.data, 1, (size_t)sz, f);
	fclose(f);
	if (argc > 3) {
		if (argv[3][0] == '-') {
			unsigned int n = (unsigned int)atoi(argv[3] + 1);
			unsigned int last = pmon_trace_last_frame(mem_read, &m, scan, sizeof(scan));

			first = last >= n ? last - n + 1 : 0;
		} else {
			first = (unsigned int)atoi(argv[3]);
		}
	}
	if (argc > 4)
		heap_cap = (unsigned int)atoi(argv[4]);

	pmon_trace_init(&t, mem_read, &m, 0x40010003, first, stage, sizeof(stage),
	                heap, heap_cap, live, PMON_LIVE_INTERVALS);
	total = pmon_trace_size(&t);
	out = (unsigned char *)malloc(total + 1);
	for (off = 0; off < total; ) {
		unsigned int n = pmon_trace_peek(&t, off, 0xF000, &d);

		if (!n)
			break;
		memcpy(out + off, d, n);
		off += n;
	}
	if (off != total) {
		fprintf(stderr, "sequential reads gave %u bytes, size pass %u\n", off, total);
		return 1;
	}
	if (pmon_trace_peek(&t, total, 0xF000, &d) != 0) {
		fprintf(stderr, "read past the end returned data\n");
		return 1;
	}
	for (i = 0; i < 60 && !fails; i++) {
		unsigned int o = rnd(total + 100), len = 1 + rnd(0x14000), n, want;

		n = pmon_trace_peek(&t, o, len, &d);
		want = o >= total ? 0 : (total - o < len ? total - o : len);
		if (want > PMON_WINDOW)
			want = PMON_WINDOW;
		if (n != want || (n && memcmp(d, out + o, n))) {
			fprintf(stderr, "window %u+%u: got %u want %u%s\n", o, len, n, want, n == want ? " (bytes differ)" : "");
			fails++;
		}
	}
	f = fopen(argv[2], "wb");
	fwrite(out, 1, total, f);
	fclose(f);
	printf("bytes=%u scenes=%u frames=%u jobs=%u bookmarks=%u samples=%u late=%u dropped=%u first=%u\n",
	       total, t.stats.scenes, t.stats.frames, t.stats.jobs, t.stats.bookmarks, t.stats.samples,
	       t.stats.late_events, t.stats.live_dropped, first);
	if (t.stats.late_events || t.stats.live_dropped || t.run.late_events || t.run.live_dropped)
		fails++;
	return fails ? 1 : 0;
}
