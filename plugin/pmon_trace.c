/*
 * pmon_trace.c -- see pmon_trace.h. Mirrors tools/pmon_synth.py: plan_jobs, build_job_intervals,
 * build_bookmarks (stable sort by time: job bookmarks, then libgxm, then frame bookmarks),
 * build_sample_groups / counted_values, interleave (bookmarks before samples at equal time),
 * pack_frames and the header of build_pmon (version 0x10002, period 1000, "overview" entries).
 */

#include "pmon_trace.h"

#ifdef PMON_HOSTED
#include <string.h>
#else
void *memset(void *d, int v, unsigned int n);
void *memcpy(void *d, const void *s, unsigned int n);
void *memmove(void *d, const void *s, unsigned int n);
#endif

#define TICKS_PER_US        333u
#define PERIOD              1000u
#define VERSION             0x10002u
#define GPU_CORES           4
#define FIRMWARE_US         20u
#define N_COUNTED           256

#define CLS_JOB             0
#define CLS_GXM             1
#define CLS_FRAME           2
#define CLS_SAMPLE          3

/* channels: fifo << 4 | regno; bookmark descriptor fifo << 12 | regno << 8 | master (0) */
#define CH_A8               0x08            /* RAZOR_GPU_GENERAL */
#define CH_B2               0x12            /* RAZOR_KERNEL_GPU_0 */
#define CH_B3               0x13            /* display driver */

#define BM_CPU_FRAME        0xB0BAFE77u
#define BM_GXM_BEGIN_SCENE  0x10000000u
#define BM_GXM_END_SCENE    0x11000000u
#define BM_GXM_KICK_BEGIN   0x1D000000u
#define BM_GXM_KICK_END     0x1E000000u
#define BM_DISP_SETFB       0x10000000u
#define BM_DISP_VBSTART     0x11000000u
#define BM_DISP_WAITVB_B    0x12000000u
#define BM_DISP_WAITVB_E    0x13000000u
#define PID_TA_BASE         0x30000000u
#define PID_3D_BASE         0x34000000u
#define PID_HIGH_FLAG       0x02000000u

/* sampled positions with the "overview" entries: register group 0 bit b on core c = c * 64 + b */
#define POS_TA(c)           ((unsigned int)(c) * 64u + 0u)
#define POS_3D(c)           ((unsigned int)(c) * 64u + 1u)
#define POS_FW              2u

static void put16(unsigned char *p, unsigned int v)
{
	p[0] = (unsigned char)v;
	p[1] = (unsigned char)(v >> 8);
}

static void put32(unsigned char *p, unsigned int v)
{
	p[0] = (unsigned char)v;
	p[1] = (unsigned char)(v >> 8);
	p[2] = (unsigned char)(v >> 16);
	p[3] = (unsigned char)(v >> 24);
}

/* --------------------------------------------------------------- output */

static void out_bytes(PmonTrace *t, const unsigned char *b, unsigned int n)
{
	if (t->len + n > t->stage_cap) {        /* cannot happen with a PMON_STAGE stage */
		t->run.late_events++;
		return;
	}
	memcpy(t->stage + t->len, b, n);
	t->len += n;
}

static void flush_frame(PmonTrace *t)
{
	if (!t->nslots)
		return;
	out_bytes(t, t->frame, PMON_FRAME_SIZE);
	memset(t->frame, 0, sizeof(t->frame));
	t->nslots = 0;
	t->body_frames++;
}

static void slot(PmonTrace *t, unsigned int desc, const unsigned char *data)
{
	put16(t->frame + 2 + t->nslots * 2, desc);
	memcpy(t->frame + 0x10 + t->nslots * 0x10, data, 16);
	if (++t->nslots == 7)
		flush_frame(t);
}

static void header(PmonTrace *t)
{
	static const unsigned int sampled_sel[4] = { 0x08000000u, 0x18001000u, 0x08020002u, 0x18021002u };
	unsigned char h[PMON_HEADER_SIZE];
	unsigned int k, c;

	memset(h, 0, sizeof(h));
	put32(h + 0x00, 0x4E4F4D50u);           /* PMON */
	put32(h + 0x0C, VERSION);
	put32(h + 0x14, t->total);              /* data end = file size (0 during the size pass) */
	put32(h + 0x20, PMON_HEADER_SIZE);      /* data start */
	put16(h + 0x30, PERIOD);
	put16(h + 0x32, PERIOD);
	for (k = 0; k < 8; k++)                 /* all 256 counted channels */
		put32(h + 0x34 + 4 * k, 0xFFFFFFFFu);
	for (k = 0; k < 4; k++)
		for (c = 0; c < 4; c++)
			put32(h + 0x74 + 0x10 * k + 4 * c, sampled_sel[k]);
	put32(h + 0xE0, 0x4E4F4D51u);           /* PMNQ */
	out_bytes(t, h, sizeof(h));
}

/* ----------------------------------------------------------------- heap */

static int ev_less(const PmonEvent *a, const PmonEvent *b)
{
	if (a->t != b->t)
		return a->t < b->t;
	if (a->cls != b->cls)
		return a->cls < b->cls;
	return a->seq < b->seq;
}

static void heap_push(PmonTrace *t, const PmonEvent *e)
{
	unsigned int i;

	if (t->nheap == t->heap_cap)
		return;                             /* the caller pops before pushing */
	i = t->nheap++;
	while (i > 0) {
		unsigned int p = (i - 1) / 2;

		if (!ev_less(e, &t->heap[p]))
			break;
		t->heap[i] = t->heap[p];
		i = p;
	}
	t->heap[i] = *e;
}

static void heap_pop(PmonTrace *t, PmonEvent *out)
{
	PmonEvent last;
	unsigned int i = 0;

	*out = t->heap[0];
	last = t->heap[--t->nheap];
	for (;;) {
		unsigned int c = 2 * i + 1;

		if (c >= t->nheap)
			break;
		if (c + 1 < t->nheap && ev_less(&t->heap[c + 1], &t->heap[c]))
			c++;
		if (!ev_less(&t->heap[c], &last))
			break;
		t->heap[i] = t->heap[c];
		i = c;
	}
	if (t->nheap)
		t->heap[i] = last;
}

static void emit(PmonTrace *t, const PmonEvent *e);

static void push(PmonTrace *t, int cls, pm_u64 us, unsigned int chan, unsigned int word)
{
	PmonEvent e;

	/* A full heap sends its earliest event out now, possibly before a later line's. */
	while (t->nheap >= t->heap_cap) {
		PmonEvent first;

		heap_pop(t, &first);
		t->run.late_events++;
		emit(t, &first);
	}
	e.t = us * TICKS_PER_US;
	e.seq = t->seq[cls]++;
	e.word = word;
	e.cls = (unsigned char)cls;
	e.chan = (unsigned char)chan;
	e.bmdesc = (unsigned short)(((chan >> 4) & 1) << 12 | (chan & 0xF) << 8);
	heap_push(t, &e);
	if (cls == CLS_SAMPLE) {
		if (!t->have_sample || us > t->max_sample_us)
			t->max_sample_us = us;
		t->have_sample = 1;
	} else {
		t->run.bookmarks++;
	}
}

/* An activity interval, and (once per distinct interval) its sample instants: start, end and
 * midpoint. The four cores share one interval's instants; repeats are dropped when emitted. */
static void add_interval(PmonTrace *t, pm_u64 a, pm_u64 b, unsigned int pos, int instants)
{
	if (t->nlive == t->live_cap) {
		t->run.live_dropped++;
	} else {
		t->live[t->nlive].a = a;
		t->live[t->nlive].b = b;
		t->live[t->nlive].pos = pos;
		t->nlive++;
	}
	if (instants) {
		push(t, CLS_SAMPLE, a, 0, 0);
		push(t, CLS_SAMPLE, b, 0, 0);
		push(t, CLS_SAMPLE, (a + b) / 2, 0, 0);
	}
}

/* round(num / den) with ties to even, as Python's round() */
static pm_u64 div_round_even(pm_u64 num, pm_u64 den)
{
	pm_u64 q = num / den, r = num - q * den;

	if (2 * r > den || (2 * r == den && (q & 1)))
		q++;
	return q;
}

static void emit_sample(PmonTrace *t, pm_u64 us)
{
	unsigned int words[8];
	static unsigned short counted[N_COUNTED];   /* too big for a syscall-sized stack */
	unsigned char s[16];
	pm_u64 tk = us * TICKS_PER_US;
	unsigned int i, k, n;

	memset(words, 0, sizeof(words));
	memset(counted, 0, sizeof(counted));
	for (i = 0; i < t->nlive; i++) {
		const PmonLive *l = &t->live[i];

		if (l->a <= us && us < l->b)
			words[l->pos >> 5] |= 1u << (l->pos & 31);
		if (t->have_last_sample && l->a < us && l->b > t->last_sample_us) {
			pm_u64 lo = l->a > t->last_sample_us ? l->a : t->last_sample_us;
			pm_u64 hi = l->b < us ? l->b : us;

			if (hi > lo) {
				pm_u64 v = div_round_even((pm_u64)PERIOD * (hi - lo), us - t->last_sample_us);

				if (v < 1)
					v = 1;
				v += counted[l->pos];
				counted[l->pos] = (unsigned short)(v > PERIOD ? PERIOD : v);
			}
		}
	}

	/* sampled packet: 3 slots */
	memset(s, 0, sizeof(s));
	put32(s, (unsigned int)tk);
	put16(s + 4, (unsigned int)(tk >> 32));
	put32(s + 8, words[0]);
	put32(s + 12, words[1]);
	slot(t, 0x6000, s);
	for (i = 0; i < 4; i++)
		put32(s + 4 * i, words[2 + i]);
	slot(t, 0x6001, s);
	memset(s, 0, sizeof(s));
	put32(s, words[6]);
	put32(s + 4, words[7]);
	slot(t, 0x6002, s);

	/* counted packet: 5 values in the first slot, then 8 per slot */
	put32(s, (unsigned int)tk);
	put16(s + 4, (unsigned int)(tk >> 32));
	for (i = 0; i < 5; i++)
		put16(s + 6 + 2 * i, counted[i]);
	slot(t, 0x6100, s);
	for (k = 1, n = 5; n < N_COUNTED; k++) {
		memset(s, 0, sizeof(s));
		for (i = 0; i < 8 && n < N_COUNTED; i++, n++)
			put16(s + 2 * i, counted[n]);
		slot(t, 0x6100 | k, s);
	}
	t->run.samples++;

	/* intervals that ended cannot reach a later period */
	for (i = 0; i < t->nlive; ) {
		if (t->live[i].b <= us)
			t->live[i] = t->live[--t->nlive];
		else
			i++;
	}
	t->last_sample_us = us;
	t->have_last_sample = 1;
}

static void emit(PmonTrace *t, const PmonEvent *e)
{
	unsigned char s[16];

	if (e->cls == CLS_SAMPLE) {
		pm_u64 us = e->t / TICKS_PER_US;

		if (t->have_last_sample && us == t->last_sample_us)
			return;                         /* the same instant from another interval */
		emit_sample(t, us);
		return;
	}
	memset(s, 0, sizeof(s));
	put32(s, (unsigned int)e->t);
	put16(s + 4, (unsigned int)(e->t >> 32));
	put16(s + 10, e->bmdesc);
	put32(s + 12, e->word);
	slot(t, 0x7F00 | e->chan, s);
}

/* ---------------------------------------------------------------- input */

/* Next line into t->line (NUL terminated, cut at PMON_LINE_MAX - 1). 0 at the end. */
static int next_line(PmonTrace *t)
{
	unsigned int n = 0;
	int any = 0;

	for (;;) {
		char c;

		if (t->rd_pos == t->rd_len) {
			int r = t->read(t->ctx, t->in_off, t->rd, sizeof(t->rd));

			if (r < 0)
				t->read_error = r;
			if (r <= 0) {
				t->line[n] = 0;
				return any;
			}
			t->in_off += (unsigned int)r;
			t->rd_pos = 0;
			t->rd_len = (unsigned int)r;
		}
		c = t->rd[t->rd_pos++];
		any = 1;
		if (c == '\n') {
			t->line[n] = 0;
			return 1;
		}
		if (c != '\r' && n < sizeof(t->line) - 1)
			t->line[n++] = c;
	}
}

/* Splits the line at commas: up to max field starts; returns the number of fields. */
static unsigned int split(char *line, char **f, unsigned int max)
{
	unsigned int n = 0;
	char *p = line;

	f[n++] = p;
	for (; *p; p++) {
		if (*p == ',') {
			*p = 0;
			if (n < max)
				f[n] = p + 1;
			n++;
		}
	}
	return n;
}

static int parse_u64(const char *s, pm_u64 *v)
{
	pm_u64 x = 0;

	if (*s == '+')
		s++;
	if (*s < '0' || *s > '9')
		return 0;
	while (*s >= '0' && *s <= '9')
		x = x * 10 + (pm_u64)(*s++ - '0');
	if (*s)
		return 0;
	*v = x;
	return 1;
}

static void scene_line(PmonTrace *t, char **f)
{
	pm_u64 v[17];
	unsigned int i, c;
	pm_u64 v0, v1, f0, f1, open, endcall, submit, done;
	unsigned int frame, draws;

	/* S,frame,fence,kind,width,height,draws,indices,open,endcall,submit,done,gpu,queue,serial */
	for (i = 1; i <= 14; i++) {
		if (i == 3)
			continue;
		if (!parse_u64(f[i], &v[i]))
			return;
	}
	frame = (unsigned int)v[1];
	draws = (unsigned int)v[6];
	open = v[8];
	endcall = v[9];
	submit = v[10];
	done = v[11];
	if (frame < t->first_frame || done == 0)
		return;
	t->run.scenes++;
	if (done > t->max_line_us)
		t->max_line_us = done;

	push(t, CLS_GXM, open, CH_A8, BM_GXM_BEGIN_SCENE);
	push(t, CLS_GXM, endcall, CH_A8, BM_GXM_END_SCENE);
	if (submit > endcall) {
		push(t, CLS_GXM, endcall, CH_A8, BM_GXM_KICK_BEGIN);
		push(t, CLS_GXM, submit, CH_A8, BM_GXM_KICK_END);
	}

	v0 = endcall;
	v1 = submit;
	if (t->have_v && v0 < t->last_v_end + 1)
		v0 = t->last_v_end + 1;
	f0 = submit;
	f1 = done;
	if (t->have_f && f0 < t->last_f_end + 1)
		f0 = t->last_f_end + 1;
	if (v1 <= v0 || f1 <= f0)
		return;
	t->run.jobs += 2;

	push(t, CLS_JOB, v0, CH_B2, 0x10000000u | (frame & 0xFFFFFF));
	push(t, CLS_JOB, v0, CH_B2, PID_TA_BASE | (t->pid & 0xFFFF));
	push(t, CLS_JOB, v0, CH_B2, PID_TA_BASE | PID_HIGH_FLAG | ((t->pid >> 16) & 0xFFFF));
	push(t, CLS_JOB, v0, CH_B2, 0x20000000u | 0x3);          /* TAFLAGS FIRSTKICK | LASTKICK */
	push(t, CLS_JOB, v1, CH_B2, 0x40000000u | (draws & 0x1FFF));
	push(t, CLS_JOB, f0, CH_B2, 0x14000000u | 1);            /* MT LLS */
	push(t, CLS_JOB, f0, CH_B2, 0x11000000u | (frame & 0xFFFFFF));
	push(t, CLS_JOB, f0, CH_B2, PID_3D_BASE | (t->pid & 0xFFFF));
	push(t, CLS_JOB, f0, CH_B2, PID_3D_BASE | PID_HIGH_FLAG | ((t->pid >> 16) & 0xFFFF));
	push(t, CLS_JOB, f0, CH_B2, 0x50000000u);                /* RENDERFLAGS 0 */

	for (c = 0; c < GPU_CORES; c++)
		add_interval(t, v0, v1, POS_TA(c), c == 0);
	add_interval(t, v0, v1 < v0 + FIRMWARE_US ? v1 : v0 + FIRMWARE_US, POS_FW, 1);
	for (c = 0; c < GPU_CORES; c++)
		add_interval(t, f0, f1, POS_3D(c), c == 0);
	add_interval(t, f0, f1 < f0 + FIRMWARE_US ? f1 : f0 + FIRMWARE_US, POS_FW, 1);

	t->last_v_end = v1;
	t->last_f_end = f1;
	t->have_v = t->have_f = 1;
}

static void frame_line(PmonTrace *t, char **f)
{
	pm_u64 v[15];
	unsigned int i;
	pm_u64 end;

	/* F,frame,start,end,scenes,game,render,beginscene,endscene,flip,throttle,present,stall,sleep,dropped */
	for (i = 1; i <= 14; i++)
		if (!parse_u64(f[i], &v[i]))
			return;
	if (v[1] < t->first_frame)
		return;
	end = v[3];
	t->run.frames++;
	if (end > t->max_line_us)
		t->max_line_us = end;
	push(t, CLS_FRAME, end, CH_A8, BM_CPU_FRAME);
	push(t, CLS_FRAME, end, CH_B3, BM_DISP_SETFB);
	push(t, CLS_FRAME, end, CH_B3, BM_DISP_VBSTART);
	push(t, CLS_FRAME, end - 1, CH_B3, BM_DISP_WAITVB_B);
	push(t, CLS_FRAME, end, CH_B3, BM_DISP_WAITVB_E);
}

static void parse_line(PmonTrace *t)
{
	char *f[17];
	unsigned int n;

	if (!next_line(t)) {
		t->input_done = 1;
		return;
	}
	if (t->line[0] == '#' || t->line[0] == 0)
		return;
	n = split(t->line, f, 17);
	if (t->line[0] == 'S' && t->line[1] == 0 && n >= 17)
		scene_line(t, f);
	else if (t->line[0] == 'F' && t->line[1] == 0 && n >= 15)
		frame_line(t, f);
}

/* ------------------------------------------------------------- stepping */

static void restart(PmonTrace *t)
{
	t->base = 0;
	t->len = 0;
	t->in_off = 0;
	t->rd_pos = t->rd_len = 0;
	t->input_done = t->trailing_done = t->finished = 0;
	t->nheap = 0;
	memset(t->seq, 0, sizeof(t->seq));
	t->max_line_us = 0;
	t->max_sample_us = 0;
	t->have_sample = 0;
	t->last_sample_us = 0;
	t->have_last_sample = 0;
	t->nlive = 0;
	t->last_v_end = t->last_f_end = 0;
	t->have_v = t->have_f = 0;
	memset(t->frame, 0, sizeof(t->frame));
	t->nslots = 0;
	t->body_frames = 0;
	memset(&t->run, 0, sizeof(t->run));
	t->read_error = 0;
	header(t);
}

static void step(PmonTrace *t)
{
	unsigned int k;

	if (t->input_done && !t->trailing_done) {
		/* a trailing all-idle sample closes the last activity period; it takes its place
		 * in time order among the events still waiting */
		if (t->have_sample)
			push(t, CLS_SAMPLE, t->max_sample_us + 1, 0, 0);
		t->trailing_done = 1;
		return;
	}
	for (k = 0; k < PMON_POP_BATCH && t->nheap; k++) {
		PmonEvent e;

		/* until the input ends, only events no later line can precede */
		if (!t->input_done && t->max_line_us >= PMON_HORIZON_US &&
		    t->heap[0].t >= (t->max_line_us - PMON_HORIZON_US) * TICKS_PER_US)
			break;
		if (!t->input_done && t->max_line_us < PMON_HORIZON_US)
			break;
		heap_pop(t, &e);
		emit(t, &e);
	}
	if (k)
		return;
	if (!t->input_done) {
		parse_line(t);
		return;
	}
	if (t->nheap)
		return;
	flush_frame(t);
	t->finished = 1;
}

unsigned int pmon_trace_last_frame(PmonReadFn read, void *ctx, char *buf, unsigned int buflen)
{
	unsigned int off = 0, last = 0, pos = 0, fieldno = 0, value = 0;
	int r, kind = 0, at_start = 1, digits = 0;

	/* "S,<frame>," / "F,<frame>,": the second field */
	while ((r = read(ctx, off, buf, buflen)) > 0) {
		for (pos = 0; pos < (unsigned int)r; pos++) {
			char c = buf[pos];

			if (c == '\n') {
				at_start = 1;
				kind = 0;
				continue;
			}
			if (at_start) {
				at_start = 0;
				kind = (c == 'S' || c == 'F');
				fieldno = 0;
				value = 0;
				digits = 0;
				continue;
			}
			if (!kind)
				continue;
			if (c == ',') {
				if (fieldno == 1 && digits && value > last)
					last = value;
				if (++fieldno > 1)
					kind = 0;
				continue;
			}
			if (fieldno == 1 && c >= '0' && c <= '9') {
				value = value * 10 + (unsigned int)(c - '0');
				digits = 1;
			}
		}
		off += (unsigned int)r;
	}
	return last;
}

void pmon_trace_init(PmonTrace *t, PmonReadFn read, void *ctx, unsigned int pid,
                     unsigned int first_frame, unsigned char *stage, unsigned int stage_cap,
                     PmonEvent *heap, unsigned int heap_cap, PmonLive *live, unsigned int live_cap)
{
	memset(t, 0, sizeof(*t));
	t->read = read;
	t->ctx = ctx;
	t->pid = pid;
	t->first_frame = first_frame;
	t->stage = stage;
	t->stage_cap = stage_cap;
	t->heap = heap;
	t->heap_cap = heap_cap;
	t->live = live;
	t->live_cap = live_cap;
	restart(t);
}

unsigned int pmon_trace_size(PmonTrace *t)
{
	t->total = 0;
	restart(t);
	while (!t->finished) {
		t->base += t->len;
		t->len = 0;
		step(t);
	}
	t->total = t->base + t->len;
	t->stats = t->run;
	restart(t);                             /* ready for reads from 0, header with the size */
	return t->total;
}

unsigned int pmon_trace_peek(PmonTrace *t, unsigned int offset, unsigned int len, const unsigned char **data)
{
	unsigned int avail;

	*data = t->stage;
	if (len > PMON_WINDOW)
		len = PMON_WINDOW;
	if (offset < t->base)
		restart(t);
	for (;;) {
		unsigned int drop = offset - t->base;

		if (drop > t->len)
			drop = t->len;
		if (drop) {
			memmove(t->stage, t->stage + drop, t->len - drop);
			t->len -= drop;
			t->base += drop;
		}
		if (t->finished || t->len >= offset - t->base + len)
			break;
		if (t->stage_cap < t->len + PMON_MARGIN)
			break;
		step(t);
	}
	if (offset - t->base >= t->len)
		return 0;
	avail = t->len - (offset - t->base);
	if (len > avail)
		len = avail;
	*data = t->stage + (offset - t->base);
	return len;
}
