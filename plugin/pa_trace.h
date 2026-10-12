/*
 * pa_trace.h -- turns rrc_pa's sampler records into a Razor PA trace (pa_encode.h)
 * in bounded memory.
 *
 * The whole trace is never held at once: a size pass runs the encoder to the end
 * discarding its output, and reads re-run it, keeping only a window of frames in a
 * fixed stage buffer. Sequential reads (what Razor does) continue where the previous
 * one stopped; a read before the stage restarts the encoder. The output is the same
 * byte for byte as encoding everything into one buffer (tools/check_pa_trace.py).
 *
 * Plain C like pa_encode.c: the kernel module and a host test build the same file.
 */

#ifndef PA_TRACE_H
#define PA_TRACE_H

#include "pa_encode.h"

#define PA_REC_HAS_PC       0x1

/* One sampler record: thread `tid` ran `run_us` on `cpu` since the previous tick,
 * which fired at `t`. 28 bytes. */
typedef struct PaRecord {
	unsigned int   t_lo, t_hi;          /* sample time, microseconds */
	unsigned char  cpu;
	unsigned char  status;              /* thread status at the sample */
	unsigned short flags;               /* PA_REC_* */
	unsigned int   tid;                 /* user thread id */
	unsigned int   run_us;
	unsigned int   pc;                  /* user PC, bit 0 = Thumb */
	int            prio;
} PaRecord;

/* Largest read, and the stage a PaTrace needs for it. One encoder step handles at most
 * PA_TRACE_MAX_GROUP records and writes at most 14 slots per record (six bookmarks of
 * up to two slots each plus a PC sample of up to two) plus the closing packets. */
#define PA_TRACE_WINDOW     0x10000u
#define PA_TRACE_MAX_GROUP  128u
#define PA_TRACE_MARGIN     ((((PA_TRACE_MAX_GROUP * 14u) + 64u) / PA_SLOTS_PER_FRAME + 2u) * PA_FRAME_SIZE)
#define PA_TRACE_STAGE      (PA_TRACE_WINDOW + PA_FRAME_SIZE + PA_TRACE_MARGIN)

typedef struct PaTraceOpen {
	int          active;
	unsigned int tid;
	int          prio;
	int          status;
	pa_u64       start, end;            /* microseconds */
} PaTraceOpen;

typedef struct PaTrace {
	/* input, fixed by pa_trace_init */
	const PaRecord *ring;
	unsigned int    ring_cap, head, count;
	unsigned int    pid, period_us, fallback_tid;
	unsigned char  *stage;
	unsigned int    stage_cap;

	/* results of pa_trace_size */
	unsigned int    total;
	unsigned int    intervals;
	unsigned int    samples;
	int             overflow;

	/* encoder state */
	PaWriter        w;                  /* w.buf = stage, w.len = complete frames held */
	unsigned int    base;               /* trace offset of stage[0] */
	unsigned int    next;               /* next record, in ring order */
	int             finished;
	pa_u64          origin, slack;
	PaTraceOpen     open[PA_MAX_CPUS];
	pa_u64          last_end[PA_MAX_CPUS];
} PaTrace;

/* Sorts `count` records starting at ring index `head` by (time, cpu), in place. The
 * per-CPU streams are already in order, so insertion sort is close to linear. */
void pa_trace_sort(PaRecord *ring, unsigned int ring_cap, unsigned int head, unsigned int count);

/* The records must stay unchanged while the trace is read. `stage_cap` must be at least
 * PA_TRACE_STAGE. `fallback_tid` names a real thread of `pid` for the one interval
 * emitted when the records produce none (Razor abandons a trace without intervals). */
void pa_trace_init(PaTrace *t, const PaRecord *ring, unsigned int ring_cap, unsigned int head,
                   unsigned int count, unsigned int pid, unsigned int period_us,
                   unsigned int fallback_tid, unsigned char *stage, unsigned int stage_cap);

/* Encodes everything once, discarding the output; sets and returns t->total. */
unsigned int pa_trace_size(PaTrace *t);

/* Makes trace bytes [offset, offset + len) available: returns how many (0 at the end,
 * at most PA_TRACE_WINDOW) and points *data at them inside the stage. The pointer is
 * valid until the next call. */
unsigned int pa_trace_peek(PaTrace *t, unsigned int offset, unsigned int len, const unsigned char **data);

/* pa_trace_peek plus a copy into dst. */
unsigned int pa_trace_read(PaTrace *t, unsigned int offset, unsigned char *dst, unsigned int len);

#endif
