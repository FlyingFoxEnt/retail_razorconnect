/*
 * pa_trace.c -- see pa_trace.h. The encoding rules are the ones rrc_pa.c used to apply
 * to the whole trace in one pass (verified in Razor on the console, 15/09): per core,
 * the records of one tick are laid out back to back ending at the tick, blocked threads
 * first and the preempted (READY) thread last, and a thread that keeps running across
 * ticks stays one interval. Added since: a thread is open on one core at a time
 * (close_elsewhere).
 */

#include "pa_trace.h"

#ifdef PA_HOSTED
#include <string.h>
#else
/* Freestanding: the module that links this file provides them. */
void *memset(void *d, int v, unsigned int n);
void *memcpy(void *d, const void *s, unsigned int n);
void *memmove(void *d, const void *s, unsigned int n);
#endif

#define REC(t, i)   (&(t)->ring[((t)->head + (i)) % (t)->ring_cap])

static pa_u64 rec_time(const PaRecord *r)
{
	return ((pa_u64)r->t_hi << 32) | r->t_lo;
}

void pa_trace_sort(PaRecord *ring, unsigned int ring_cap, unsigned int head, unsigned int count)
{
	unsigned int i, j;

	for (i = 1; i < count; i++) {
		PaRecord tmp = ring[(head + i) % ring_cap];
		pa_u64 t = rec_time(&tmp);

		j = i;
		while (j > 0) {
			PaRecord *p = &ring[(head + j - 1) % ring_cap];

			if (rec_time(p) < t || (rec_time(p) == t && p->cpu <= tmp.cpu))
				break;
			ring[(head + j) % ring_cap] = *p;
			j--;
		}
		ring[(head + j) % ring_cap] = tmp;
	}
}

static pa_u64 ticks(const PaTrace *t, pa_u64 us)
{
	return (us - t->origin) * PA_TICKS_PER_US + 333000ull;   /* +1 ms: room before the first switch */
}

static void close_open(PaTrace *t, int cpu)
{
	PaTraceOpen *o = &t->open[cpu];

	if (!o->active)
		return;
	pa_switch_out(&t->w, cpu, ticks(t, o->end), t->pid, o->tid,
	              o->status == 2 ? PA_THREAD_READY : PA_THREAD_WAITING);
	o->active = 0;
}

/* A thread runs on one core at a time, and Razor pairs switch packets per thread in
 * buffer order ("Scheduler trace missing events" otherwise, and the interval is lost).
 * A thread that moved cores is still open on the old one until that core's next record,
 * so before switching it in on `cpu` at *cursor, close it there first, ending before
 * *cursor. If that interval started too recently to end in time, *cursor moves later. */
static void close_elsewhere(PaTrace *t, int cpu, unsigned int tid, pa_u64 *cursor)
{
	int c;

	for (c = 0; c < PA_MAX_CPUS; c++) {
		PaTraceOpen *o = &t->open[c];

		if (c == cpu || !o->active || o->tid != tid)
			continue;
		if (*cursor < o->start + 2)
			*cursor = o->start + 2;
		if (o->end > *cursor - 1)
			o->end = *cursor - 1;
		if (o->end <= o->start)
			o->end = o->start + 1;
		close_open(t, c);
	}
}

static void restart(PaTrace *t)
{
	pa_init(&t->w, t->stage, t->stage_cap);
	t->base = 0;
	t->next = 0;
	t->finished = 0;
	memset(t->open, 0, sizeof(t->open));
	memset(t->last_end, 0, sizeof(t->last_end));
	t->origin = 0;
	if (t->count) {
		const PaRecord *r = REC(t, 0);
		pa_u64 first = rec_time(r);

		t->origin = first > r->run_us ? first - r->run_us : 0;
	}
	t->slack = (pa_u64)t->period_us + t->period_us / 2;
}

void pa_trace_init(PaTrace *t, const PaRecord *ring, unsigned int ring_cap, unsigned int head,
                   unsigned int count, unsigned int pid, unsigned int period_us,
                   unsigned int fallback_tid, unsigned char *stage, unsigned int stage_cap)
{
	memset(t, 0, sizeof(*t));
	t->ring = ring;
	t->ring_cap = ring_cap;
	t->head = head;
	t->count = count;
	t->pid = pid;
	t->period_us = period_us;
	t->fallback_tid = fallback_tid;
	t->stage = stage;
	t->stage_cap = stage_cap;
	restart(t);
}

/* Encodes one core's records for one tick (at most PA_TRACE_MAX_GROUP of them), or,
 * once the records are used up, closes the open intervals and finishes the buffer. */
static void step(PaTrace *t)
{
	PaWriter *w = &t->w;

	if (t->next < t->count) {
		unsigned int i = t->next, k, j, lim;
		const PaRecord *r0 = REC(t, i);
		pa_u64 time = rec_time(r0), total = 0, cursor;
		int cpu = r0->cpu, pass;

		lim = t->count - i > PA_TRACE_MAX_GROUP ? i + PA_TRACE_MAX_GROUP : t->count;
		for (k = i; k < lim; k++) {
			const PaRecord *r = REC(t, k);

			if (rec_time(r) != time || r->cpu != cpu)
				break;
			total += r->run_us;
		}
		t->next = k;
		if (cpu >= PA_MAX_CPUS)
			return;
		if (total > time - t->origin)
			total = time - t->origin;
		cursor = time - total;
		if (cursor < t->last_end[cpu])
			cursor = t->last_end[cpu];

		for (pass = 0; pass < 2; pass++) {      /* blocked threads, then READY ones */
			for (j = i; j < k; j++) {
				const PaRecord *r = REC(t, j);
				PaTraceOpen *o = &t->open[cpu];
				pa_u64 end;

				if ((pass == 0) != (r->status != 2))
					continue;
				end = cursor + r->run_us;
				if (end > time)
					end = time;
				if (end <= cursor)
					end = cursor + 1;
				if (o->active && (o->tid != r->tid || cursor > o->end + t->slack))
					close_open(t, cpu);
				if (!o->active) {
					pa_u64 was = cursor;

					close_elsewhere(t, cpu, r->tid, &cursor);
					if (cursor != was) {
						end = cursor + r->run_us;
						if (end > time)
							end = time;
						if (end <= cursor)
							end = cursor + 1;
					}
					o->active = 1;
					o->tid = r->tid;
					o->prio = r->prio;
					o->start = cursor;
					pa_switch_in(w, cpu, ticks(t, cursor), t->pid, r->tid, r->prio);
				}
				o->end = end;
				o->status = r->status;
				if (r->flags & PA_REC_HAS_PC)
					pa_pc_sample(w, cpu, r->pc);
				cursor = end;
			}
		}
		t->last_end[cpu] = cursor;
		return;
	}

	{
		int c;

		for (c = 0; c < PA_MAX_CPUS; c++)
			close_open(t, c);
	}
	/* Razor abandons a CPU trace with no closed interval at all. Give it one short
	 * interval of a real thread (a made-up id 0 is rejected as a duplicate object). */
	if (w->intervals == 0) {
		pa_switch_in(w, 0, ticks(t, t->origin + 1), t->pid, t->fallback_tid, 160);
		pa_switch_out(w, 0, ticks(t, t->origin + 2), t->pid, t->fallback_tid, PA_THREAD_WAITING);
	}
	pa_finish(w);
	t->finished = 1;
}

unsigned int pa_trace_size(PaTrace *t)
{
	restart(t);
	while (!t->finished) {
		t->base += t->w.len;
		t->w.len = 0;
		step(t);
	}
	t->total = t->base + t->w.len;
	t->intervals = t->w.intervals;
	t->samples = t->w.samples;
	t->overflow = t->w.overflow;
	return t->total;
}

unsigned int pa_trace_peek(PaTrace *t, unsigned int offset, unsigned int len, const unsigned char **data)
{
	unsigned int avail;

	*data = t->stage;
	if (len > PA_TRACE_WINDOW)
		len = PA_TRACE_WINDOW;
	if (offset < t->base)
		restart(t);
	for (;;) {
		/* Frames that end at or before `offset` are no longer needed. */
		unsigned int drop = (offset - t->base) / PA_FRAME_SIZE * PA_FRAME_SIZE;

		if (drop > t->w.len)
			drop = t->w.len;
		if (drop) {
			memmove(t->stage, t->stage + drop, t->w.len - drop);
			t->w.len -= drop;
			t->base += drop;
		}
		if (t->finished || t->w.len >= offset - t->base + len)
			break;
		/* Cannot happen with len <= PA_TRACE_WINDOW and a PA_TRACE_STAGE stage;
		 * stop rather than let the writer drop frames. */
		if (t->w.cap < t->w.len + PA_TRACE_MARGIN)
			break;
		step(t);
	}
	if (offset - t->base >= t->w.len)
		return 0;
	avail = t->w.len - (offset - t->base);
	if (len > avail)
		len = avail;
	*data = t->stage + (offset - t->base);
	return len;
}

unsigned int pa_trace_read(PaTrace *t, unsigned int offset, unsigned char *dst, unsigned int len)
{
	const unsigned char *src;
	unsigned int n = pa_trace_peek(t, offset, len, &src);

	if (n)
		memcpy(dst, src, n);
	return n;
}
