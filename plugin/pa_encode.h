/*
 * pa_encode.h -- writes a Performance Analysis (PA) trace buffer in the format
 * PS Vita Razor's CPU trace decoder reads (PSP2Razor.dll 3.60).
 *
 * Plain C with no SDK or libc dependency (the caller provides memset/memcpy),
 * so the same file builds into the kernel module and into a host test.
 * Formats: ../docs/RAZOR_PA_TRACE_FORMAT.md (frames, bookmarks, timebase),
 * ../docs/RAZOR_SYSTRACE_FORMAT.md (scheduler packets), ../docs/RAZOR_PFT_SAMPLE_FORMAT.md
 * (PC samples). The Python references are tools/pa_frames.py, pa_systrace.py
 * and pa_pft.py; tools/check_pa_encode.py decodes this encoder's output with them.
 *
 * Usage: pa_init, then events in non-decreasing time order per CPU
 * (pa_switch_in / pa_switch_out / pa_pc_sample / pa_bookmark), then pa_finish.
 * Times are 48-bit ticks of the 333 MHz PA timebase (PA_TICKS_PER_US per us).
 */

#ifndef PA_ENCODE_H
#define PA_ENCODE_H

#define PA_FRAME_SIZE        0x80
#define PA_SLOTS_PER_FRAME   7
#define PA_TICKS_PER_US      333u           /* 333 MHz */
#define PA_MAX_CPUS          4

#define PA_FIFO_A            0
#define PA_FIFO_B            1
#define PA_REGNO_SYS0        6              /* FIFO B: scheduler / syscall packets */

/* Switch-out status byte (SceThreadStatus of the outgoing thread). */
#define PA_THREAD_READY      0x02
#define PA_THREAD_WAITING    0x08

typedef unsigned long long pa_u64;

typedef struct PaWriter {
	unsigned char *buf;
	unsigned int   cap;
	unsigned int   len;                     /* bytes of complete frames */
	int            overflow;                /* a frame did not fit */

	/* current frame being filled */
	unsigned char  frame[PA_FRAME_SIZE];
	unsigned int   nslots;

	/* one 64-bit bookmark waiting to be paired into a 0x7d slot */
	int            have_pending;
	unsigned char  pending[8];

	/* running timebase: time >> 21 of the last 0x7e slot, or -1 */
	int            base_valid;
	pa_u64         base;

	/* scheduler packets: last time used per CPU (keeps them strictly increasing) */
	pa_u64         last_sys_time[PA_MAX_CPUS];
	int            sys_time_valid[PA_MAX_CPUS];

	/* PFT byte streams per CPU, sliced into 14-byte formatter frames */
	unsigned char  pft[PA_MAX_CPUS][14];
	unsigned int   pft_len[PA_MAX_CPUS];
	int            pft_synced[PA_MAX_CPUS];

	unsigned int   bookmarks;               /* statistics */
	unsigned int   samples;
	unsigned int   intervals;
} PaWriter;

void pa_init(PaWriter *w, unsigned char *buf, unsigned int cap);

/* One 64-bit bookmark (any channel). */
void pa_bookmark(PaWriter *w, int fifo, int regno, int master, pa_u64 time, unsigned int data);

/* Scheduler events on FIFO B SYS_0; cpu 0..3. Every switch-in must be closed by a
 * switch-out on the same CPU, or Razor attributes nothing to that thread. */
void pa_switch_in(PaWriter *w, int cpu, pa_u64 time, unsigned int pid, unsigned int tid, int priority);
void pa_switch_out(PaWriter *w, int cpu, pa_u64 time, unsigned int pid, unsigned int tid, int status);

/* One PC sample for Razor's "Function Sampling" histogram (PFT I-sync). pc bit 0 = Thumb. */
void pa_pc_sample(PaWriter *w, int cpu, unsigned int pc);

/* Flushes pending PFT bytes and bookmarks and pads the last frame. Returns bytes written. */
unsigned int pa_finish(PaWriter *w);

#endif
