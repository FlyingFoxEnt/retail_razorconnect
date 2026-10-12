/*
 * pmon_trace.h -- turns the game's GPU profiler CSV (ux0:data/gxm_gpu_<unix>.csv, written by
 * GXMGpuProfiler.cpp) into the .pmon GPU trace Razor loads, on the console, in bounded memory.
 *
 * It produces the same bytes as tools/pmon_synth.py (tools/check_pmon_trace.py compares them),
 * whose rules are in ../docs/PMON_SYNTH_NOTES.md ("Round 4"). The CSV is read line by line; the events
 * of each line go into a time-ordered heap and leave it once no later line can precede them
 * (lines are at most PMON_HORIZON_US out of order). Like pa_trace, a size pass runs everything
 * with the output discarded, and reads re-run it keeping only a window of the file in a stage.
 *
 * Plain C, no SDK dependency: the SceShell plugin and a host test build the same file.
 */

#ifndef PMON_TRACE_H
#define PMON_TRACE_H

typedef unsigned long long pm_u64;

/* Reads up to len bytes of the CSV at offset: bytes read, 0 at the end, < 0 on error. */
typedef int (*PmonReadFn)(void *ctx, unsigned int offset, char *buf, unsigned int len);

#define PMON_HEADER_SIZE    0xF0u           /* PMON 0xE0 + PMNQ 0x10 */
#define PMON_FRAME_SIZE     0x80u
#define PMON_HORIZON_US     2000000u        /* how far out of time order CSV lines may be */
#define PMON_POP_BATCH      32u             /* events emitted per step */
#define PMON_STEP_EVENTS    64u             /* most events one step can emit (a CSV line pushes <= 26) */
#define PMON_GROUP_SLOTS    36u             /* one sample: 3 sampled + 33 counted slots */
#define PMON_WINDOW         0x10000u        /* largest read */
#define PMON_MARGIN         (((PMON_STEP_EVENTS * PMON_GROUP_SLOTS) / 7u + 3u) * PMON_FRAME_SIZE)
#define PMON_STAGE          (PMON_WINDOW + PMON_HEADER_SIZE + PMON_FRAME_SIZE + PMON_MARGIN)
#define PMON_READ_CHUNK     2048u
#define PMON_LINE_MAX       512u            /* the fields used are at the start; longer lines are cut */
/* Capacities for PMON_HORIZON_US of CSV (up to ~90 scenes/s): events waiting in the heap and
 * activity intervals parsed but not finished. Too small shows as late_events / live_dropped. */
#define PMON_HEAP_EVENTS    16384u
#define PMON_LIVE_INTERVALS 4096u

typedef struct PmonEvent {                  /* 24 bytes */
	pm_u64         t;                       /* ticks (us * 333) */
	unsigned int   seq;                     /* generation order within the class */
	unsigned int   word;                    /* bookmark data word; unused for samples */
	unsigned char  cls;                     /* 0 job, 1 libgxm, 2 frame bookmark, 3 sample */
	unsigned char  chan;                    /* bookmark: fifo << 4 | regno */
	unsigned short bmdesc;
} PmonEvent;

typedef struct PmonLive {                   /* an activity interval [a, b) at sampled position pos */
	pm_u64         a, b;
	unsigned int   pos;
} PmonLive;

typedef struct PmonStats {
	unsigned int    scenes, frames, jobs, bookmarks, samples;
	unsigned int    late_events;            /* left the heap before their turn (heap full) */
	unsigned int    live_dropped;           /* activity intervals that did not fit */
} PmonStats;

typedef struct PmonTrace {
	/* input, fixed by pmon_trace_init */
	PmonReadFn      read;
	void           *ctx;
	unsigned int    pid;
	unsigned int    first_frame;            /* CSV frames before this one are left out */
	unsigned char  *stage;
	unsigned int    stage_cap;
	PmonEvent      *heap;
	unsigned int    heap_cap;
	PmonLive       *live;
	unsigned int    live_cap;

	/* results of pmon_trace_size */
	unsigned int    total;                  /* file size: header + frames */
	PmonStats       stats;
	int             read_error;

	PmonStats       run;                    /* counters of the pass in progress */

	/* encoder state */
	unsigned int    base, len;              /* stage holds file bytes [base, base + len) */
	unsigned int    in_off;
	char            rd[PMON_READ_CHUNK];
	unsigned int    rd_pos, rd_len;
	char            line[PMON_LINE_MAX];
	int             input_done, trailing_done, finished;
	unsigned int    nheap;
	unsigned int    seq[4];
	pm_u64          max_line_us;
	pm_u64          max_sample_us;
	int             have_sample;
	pm_u64          last_sample_us;         /* previous emitted sample */
	int             have_last_sample;
	unsigned int    nlive;
	pm_u64          last_v_end, last_f_end;
	int             have_v, have_f;
	unsigned char   frame[PMON_FRAME_SIZE];
	unsigned int    nslots;
	unsigned int    body_frames;
} PmonTrace;

/* Highest frame number in the CSV (0 if none), to pick first_frame for "the last N frames". */
unsigned int pmon_trace_last_frame(PmonReadFn read, void *ctx, char *buf, unsigned int buflen);

void pmon_trace_init(PmonTrace *t, PmonReadFn read, void *ctx, unsigned int pid,
                     unsigned int first_frame, unsigned char *stage, unsigned int stage_cap,
                     PmonEvent *heap, unsigned int heap_cap, PmonLive *live, unsigned int live_cap);

/* Runs the whole conversion with the output discarded; sets and returns t->total. */
unsigned int pmon_trace_size(PmonTrace *t);

/* File bytes [offset, offset + len): count (0 at the end, at most PMON_WINDOW) and *data. */
unsigned int pmon_trace_peek(PmonTrace *t, unsigned int offset, unsigned int len, const unsigned char **data);

#endif
