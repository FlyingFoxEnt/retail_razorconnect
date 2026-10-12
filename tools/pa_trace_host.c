/* Host test for plugin/pa_trace.c, driven by check_pa_trace.py.
 *
 *   pa_trace_host SEED RING_CAP RECORDS OUT.raw
 *
 * Simulates rrc_pa's samplers (per-core ticks, pushes slightly out of order, a ring
 * that wraps), then encodes the records twice: with the one-pass encode() rrc_pa.c
 * used before (copied below, the version verified in Razor, plus the one-core-at-a-time
 * rule pa_trace added) into one big buffer, and
 * with pa_trace's size pass plus windowed reads in several patterns. Every read must
 * match the reference bytes. Writes the reference trace to OUT.raw and prints
 * "bytes=N intervals=N samples=N records=N". Exit status 0 = identical. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../plugin/pa_trace.h"

static unsigned int rng_state;
static unsigned int rnd(unsigned int n)
{
	rng_state = rng_state * 1103515245u + 12345u;
	return ((rng_state >> 8) & 0xFFFFFF) % (n ? n : 1);
}

/* ------------------------------------------------ the old one-pass encoder */

typedef struct Open { int active; unsigned int tid; int prio; int status; pa_u64 start, end; } Open;

static PaRecord *g_ring;
static unsigned int g_cap, g_head, g_count, g_pid = 0x40010045, g_period_us = 1000, g_fb_tid = 0x40010201;

static pa_u64 rec_time(const PaRecord *r) { return ((pa_u64)r->t_hi << 32) | r->t_lo; }
static pa_u64 old_ticks(pa_u64 us, pa_u64 origin) { return (pa_u64)(us - origin) * PA_TICKS_PER_US + 333000ull; }
static void old_close(PaWriter *w, Open *o, int cpu, pa_u64 origin)
{
	if (!o->active)
		return;
	pa_switch_out(w, cpu, old_ticks(o->end, origin), g_pid, o->tid,
	              o->status == 2 ? PA_THREAD_READY : PA_THREAD_WAITING);
	o->active = 0;
}

static unsigned int old_encode(unsigned char *out, unsigned int cap, unsigned int *intervals, unsigned int *samples)
{
	Open open[4];
	pa_u64 last_end[4];
	pa_u64 origin, slack;
	static PaWriter wr;
	PaWriter *w = &wr;
	unsigned int n = g_count, i, j;

	memset(open, 0, sizeof(open));
	memset(last_end, 0, sizeof(last_end));
	pa_init(w, out, cap);
	origin = n ? rec_time(&g_ring[g_head]) : 0;
	if (n) {
		pa_u64 first_run = g_ring[g_head].run_us;
		origin = origin > first_run ? origin - first_run : 0;
	}
	slack = g_period_us + g_period_us / 2;
	for (i = 0; i < n; ) {
		PaRecord *r0 = &g_ring[(g_head + i) % g_cap];
		pa_u64 t = rec_time(r0), total = 0, cursor;
		int cpu = r0->cpu, pass;
		unsigned int k;

		for (k = i; k < n; k++) {
			PaRecord *r = &g_ring[(g_head + k) % g_cap];
			if (rec_time(r) != t || r->cpu != cpu)
				break;
			total += r->run_us;
		}
		if (cpu >= 4) { i = k; continue; }
		if (total > t - origin)
			total = t - origin;
		cursor = t - total;
		if (cursor < last_end[cpu])
			cursor = last_end[cpu];
		for (pass = 0; pass < 2; pass++) {
			for (j = i; j < k; j++) {
				PaRecord *r = &g_ring[(g_head + j) % g_cap];
				pa_u64 end;
				if ((pass == 0) != (r->status != 2))
					continue;
				end = cursor + r->run_us;
				if (end > t) end = t;
				if (end <= cursor) end = cursor + 1;
				if (open[cpu].active && (open[cpu].tid != r->tid || cursor > open[cpu].end + slack))
					old_close(w, &open[cpu], cpu, origin);
				if (!open[cpu].active) {
					/* added with pa_trace: a thread is open on one core at a time */
					int c2;
					for (c2 = 0; c2 < 4; c2++) {
						if (c2 == cpu || !open[c2].active || open[c2].tid != r->tid)
							continue;
						if (cursor < open[c2].start + 2) {
							cursor = open[c2].start + 2;
							end = cursor + r->run_us;
							if (end > t) end = t;
							if (end <= cursor) end = cursor + 1;
						}
						if (open[c2].end > cursor - 1) open[c2].end = cursor - 1;
						if (open[c2].end <= open[c2].start) open[c2].end = open[c2].start + 1;
						old_close(w, &open[c2], c2, origin);
					}
					open[cpu].active = 1;
					open[cpu].tid = r->tid;
					open[cpu].prio = r->prio;
					open[cpu].start = cursor;
					pa_switch_in(w, cpu, old_ticks(cursor, origin), g_pid, r->tid, r->prio);
				}
				open[cpu].end = end;
				open[cpu].status = r->status;
				if (r->flags & PA_REC_HAS_PC)
					pa_pc_sample(w, cpu, r->pc);
				cursor = end;
			}
		}
		last_end[cpu] = cursor;
		i = k;
	}
	for (i = 0; i < 4; i++)
		old_close(w, &open[i], (int)i, origin);
	if (w->intervals == 0) {
		pa_switch_in(w, 0, old_ticks(origin + 1, origin), g_pid, g_fb_tid, 160);
		pa_switch_out(w, 0, old_ticks(origin + 2, origin), g_pid, g_fb_tid, PA_THREAD_WAITING);
	}
	*intervals = w->intervals;
	*samples = w->samples;
	return pa_finish(w);
}

/* ------------------------------------------------------ the sampler model */

static void push(const PaRecord *r)
{
	if (g_count == g_cap) {
		g_head = (g_head + 1) % g_cap;
		g_count--;
	}
	g_ring[(g_head + g_count) % g_cap] = *r;
	g_count++;
}

static void simulate(unsigned int records, unsigned int ncpu)
{
	static const unsigned int pcs[] = { 0x81000100, 0x81004000, 0x81000235, 0x81123450, 0x810FFFF1 };
	unsigned long long now = 5000000ull;
	PaRecord held;
	int have_held = 0;
	unsigned int made = 0, tick = 0;

	while (made < records) {
		unsigned int order[4] = { 0, 1, 2, 3 }, c, x;

		tick++;
		now += 1000 + rnd(40);
		for (c = 0; c < ncpu; c++) {           /* cores push in a random order */
			unsigned int s = rnd(ncpu), tmp = order[c];
			order[c] = order[s]; order[s] = tmp;
		}
		for (x = 0; x < ncpu && made < records; x++) {
			unsigned int cpu = order[x], n, budget = 1000, k;
			unsigned long long t = now + cpu * 7 + rnd(3);   /* each core samples at its own instant */
			int preempted;

			/* idle ticks, bursts with many threads (a fresh process; the sampler lists at
			 * most RRC_PA_MAX_THREADS = 96), and ordinary ones */
			n = rnd(10) == 0 ? 0 : (rnd(200) == 0 ? 60 + rnd(37) : 1 + rnd(4));
			preempted = n ? (int)rnd(n) : -1;
			for (k = 0; k < n && made < records; k++) {
				PaRecord r;

				memset(&r, 0, sizeof(r));
				r.t_lo = (unsigned int)t;
				r.t_hi = (unsigned int)(t >> 32);
				r.cpu = (unsigned char)cpu;
				r.tid = 0x40010201 + rnd(12);
				r.prio = 64 + (int)rnd(100);
				r.run_us = k == n - 1 ? budget : rnd(budget + 1);
				if (rnd(50) == 0)
					r.run_us = 3000 + rnd(5000);          /* ran across several ticks */
				budget -= r.run_us <= budget ? r.run_us : budget;
				r.status = (unsigned char)((int)k == preempted ? 2 : 8);
				if ((int)k == preempted && rnd(8) != 0) {
					r.flags = PA_REC_HAS_PC;
					r.pc = pcs[rnd(5)];
				}
				/* now and then a pass is delayed and lands after the next core's */
				if (!have_held && rnd(300) == 0) {
					held = r;
					have_held = 1;
				} else {
					push(&r);
				}
				made++;
			}
			if (have_held && rnd(2) == 0) {
				push(&held);
				have_held = 0;
			}
		}
	}
	if (have_held)
		push(&held);
}

/* --------------------------------------------------------------- the test */

static int check(const char *what, PaTrace *t, const unsigned char *ref, unsigned int off, unsigned int len)
{
	static unsigned char buf[PA_TRACE_WINDOW];
	unsigned int want = off >= t->total ? 0 : (t->total - off < len ? t->total - off : len);
	unsigned int got;

	if (want > PA_TRACE_WINDOW)
		want = PA_TRACE_WINDOW;
	got = pa_trace_read(t, off, buf, len);
	if (got != want || memcmp(buf, ref + off, got)) {
		fprintf(stderr, "%s: read(%u, %u) got %u want %u%s\n", what, off, len, got, want,
		        got == want ? " (bytes differ)" : "");
		return 1;
	}
	return 0;
}

int main(int argc, char **argv)
{
	static unsigned char ref[64 << 20];
	static unsigned char stage[PA_TRACE_STAGE];
	static PaTrace tr;
	unsigned int seed, records, ref_len, iv, sm, off, fails = 0, i;
	FILE *f;

	if (argc < 5)
		return 2;
	seed = (unsigned int)strtoul(argv[1], 0, 0);
	g_cap = (unsigned int)strtoul(argv[2], 0, 0);
	records = (unsigned int)strtoul(argv[3], 0, 0);
	rng_state = seed;
	g_ring = (PaRecord *)calloc(g_cap, sizeof(PaRecord));
	simulate(records, 3 + seed % 2);
	pa_trace_sort(g_ring, g_cap, g_head, g_count);
	for (i = 1; i < g_count; i++) {
		PaRecord *a = &g_ring[(g_head + i - 1) % g_cap], *b = &g_ring[(g_head + i) % g_cap];
		if (rec_time(a) > rec_time(b) || (rec_time(a) == rec_time(b) && a->cpu > b->cpu)) {
			fprintf(stderr, "sort: records %u and %u out of order\n", i - 1, i);
			return 1;
		}
	}

	ref_len = old_encode(ref, sizeof(ref), &iv, &sm);

	pa_trace_init(&tr, g_ring, g_cap, g_head, g_count, g_pid, g_period_us, g_fb_tid, stage, sizeof(stage));
	if (pa_trace_size(&tr) != ref_len || tr.intervals != iv || tr.samples != sm || tr.overflow) {
		fprintf(stderr, "size pass: %u bytes %u intervals %u samples (overflow %d), reference %u / %u / %u\n",
		        tr.total, tr.intervals, tr.samples, tr.overflow, ref_len, iv, sm);
		return 1;
	}
	/* Razor's pattern: the plugin reads 0xF000 at a time from 0. */
	for (off = 0; off <= ref_len && !fails; off += 0xF000)
		fails += check("sequential 0xF000", &tr, ref, off, 0xF000);
	/* odd sizes, not frame aligned */
	for (off = 0; off < ref_len && !fails; ) {
		unsigned int len = 1 + rnd(0x12000);
		fails += check("sequential odd", &tr, ref, off, len);
		off += len > PA_TRACE_WINDOW ? PA_TRACE_WINDOW : len;
	}
	/* random offsets, including backwards (restart) */
	for (i = 0; i < 40 && !fails; i++)
		fails += check("random", &tr, ref, rnd(ref_len + 300), 1 + rnd(0x10000));
	/* re-reading the last chunk and reading past the end */
	if (!fails && ref_len > 100)
		fails += check("tail", &tr, ref, ref_len - 100, 0xF000);
	if (!fails)
		fails += check("past end", &tr, ref, ref_len, 0xF000);

	f = fopen(argv[4], "wb");
	fwrite(ref, 1, ref_len, f);
	fclose(f);
	printf("bytes=%u intervals=%u samples=%u records=%u\n", ref_len, iv, sm, g_count);
	return fails ? 1 : 0;
}
