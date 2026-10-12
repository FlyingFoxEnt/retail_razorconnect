/*
 * pa_encode.c -- see pa_encode.h. Mirrors tools/pa_frames.py (frame packing and the
 * 0x7e timebase rule), tools/pa_systrace.py (switch packets) and tools/pa_pft.py
 * (A-sync, I-sync, CoreSight formatter frames).
 */

#include "pa_encode.h"

#ifdef PA_HOSTED
#include <string.h>
#else
/* Freestanding: the module that links this file provides them. */
void *memset(void *d, int v, unsigned int n);
void *memcpy(void *d, const void *s, unsigned int n);
#endif

#define SLOT_PFT        0x10
#define SLOT_BM64X1     0x7c
#define SLOT_BM64X2     0x7d
#define SLOT_BM_TS      0x7e

#define PKT_SWITCH_IN   2
#define PKT_SWITCH_OUT  3

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

void pa_init(PaWriter *w, unsigned char *buf, unsigned int cap)
{
	memset(w, 0, sizeof(*w));
	w->buf = buf;
	w->cap = cap;
}

/* ---------------------------------------------------------------- frames */

static void flush_frame(PaWriter *w)
{
	if (w->nslots == 0)
		return;
	if (w->len + PA_FRAME_SIZE <= w->cap) {
		memcpy(w->buf + w->len, w->frame, PA_FRAME_SIZE);
		w->len += PA_FRAME_SIZE;
	} else {
		w->overflow = 1;
	}
	memset(w->frame, 0, sizeof(w->frame));
	w->nslots = 0;
}

/* Frame = u16 0 | 7 x u16 slot descriptor | 7 x 16-byte slot. */
static void emit_slot(PaWriter *w, unsigned int desc, const unsigned char *payload)
{
	put16(w->frame + 2 + w->nslots * 2, desc);
	memcpy(w->frame + 0x10 + w->nslots * 0x10, payload, 16);
	if (++w->nslots == PA_SLOTS_PER_FRAME)
		flush_frame(w);
}

static void flush_pending(PaWriter *w)
{
	unsigned char slot[16];

	if (!w->have_pending)
		return;
	memset(slot, 0, sizeof(slot));
	memcpy(slot, w->pending, 8);
	emit_slot(w, SLOT_BM64X1 << 8, slot);
	w->have_pending = 0;
}

/* ------------------------------------------------------------- bookmarks */

/* w0 = fifo<<31 | regno<<27 | master<<21 | time[20:0], w1 = data. A bookmark takes its
 * upper time bits from the last 0x7e slot, so a new 0x7e slot (carrying this bookmark)
 * is emitted whenever time >> 21 changes. */
void pa_bookmark(PaWriter *w, int fifo, int regno, int master, pa_u64 time, unsigned int data)
{
	unsigned char words[8], slot[16];
	pa_u64 t = time & 0xFFFFFFFFFFFFull;

	put32(words, ((unsigned int)(fifo & 1) << 31) | ((unsigned int)(regno & 0xF) << 27) |
	             ((unsigned int)(master & 0x3F) << 21) | ((unsigned int)t & 0x1FFFFF));
	put32(words + 4, data);
	w->bookmarks++;

	if (!w->base_valid || (t >> 21) != w->base) {
		flush_pending(w);
		w->base_valid = 1;
		w->base = t >> 21;
		put32(slot, (unsigned int)t);
		put16(slot + 4, (unsigned int)(t >> 32));
		put16(slot + 6, 0);
		memcpy(slot + 8, words, 8);
		emit_slot(w, SLOT_BM_TS << 8, slot);
	} else if (!w->have_pending) {
		memcpy(w->pending, words, 8);
		w->have_pending = 1;
	} else {
		memcpy(slot, w->pending, 8);
		memcpy(slot + 8, words, 8);
		emit_slot(w, SLOT_BM64X2 << 8, slot);
		w->have_pending = 0;
	}
}

/* ------------------------------------------------------ scheduler packets */

/* Packet words ride consecutive SYS_0 bookmarks of master cpu+1; Razor uses the
 * header bookmark's time. Times per CPU must strictly increase. */
static void sys_packet(PaWriter *w, int cpu, pa_u64 time, const unsigned int *words, int n)
{
	int i;

	if (cpu < 0 || cpu >= PA_MAX_CPUS)
		return;
	if (w->sys_time_valid[cpu] && time <= w->last_sys_time[cpu])
		time = w->last_sys_time[cpu] + 1;
	for (i = 0; i < n; i++)
		pa_bookmark(w, PA_FIFO_B, PA_REGNO_SYS0, cpu + 1, time + (pa_u64)i, words[i]);
	w->last_sys_time[cpu] = time + (pa_u64)(n - 1);
	w->sys_time_valid[cpu] = 1;
}

static unsigned int header_word(int type, int words, unsigned int b1, unsigned int b0)
{
	return ((unsigned int)type << 24) | ((unsigned int)(words * 4) << 16) |
	       ((b1 & 0xFF) << 8) | (b0 & 0xFF);
}

void pa_switch_in(PaWriter *w, int cpu, pa_u64 time, unsigned int pid, unsigned int tid, int priority)
{
	unsigned int p[3];

	p[0] = header_word(PKT_SWITCH_IN, 3, (unsigned int)priority, 0);
	p[1] = pid;
	p[2] = tid;
	sys_packet(w, cpu, time, p, 3);
}

void pa_switch_out(PaWriter *w, int cpu, pa_u64 time, unsigned int pid, unsigned int tid, int status)
{
	unsigned int p[3];

	p[0] = header_word(PKT_SWITCH_OUT, 3, 0, (unsigned int)status);
	p[1] = pid;
	p[2] = tid;
	sys_packet(w, cpu, time, p, 3);
	w->intervals++;
}

/* ------------------------------------------------------------ PC samples */

/* One CoreSight formatter frame for trace ID cpu+1: byte 0 = ID (immediate),
 * bytes 1..14 data (padded with 0x66 Ignore), byte 15 = aux holding bit 0 of the
 * even-position data bytes. */
static void pft_emit_frame(PaWriter *w, int cpu)
{
	unsigned char slot[16];
	unsigned int i, aux = 0;

	flush_pending(w);
	slot[0] = (unsigned char)(((cpu + 1) << 1) | 1);
	for (i = 0; i < 14; i++) {
		unsigned int pos = i + 1;
		unsigned char d = i < w->pft_len[cpu] ? w->pft[cpu][i] : 0x66;

		if (pos & 1) {
			slot[pos] = d;
		} else {
			slot[pos] = (unsigned char)(d & 0xFE);
			aux |= (unsigned int)(d & 1) << (pos >> 1);
		}
	}
	slot[15] = (unsigned char)aux;
	emit_slot(w, (SLOT_PFT << 8) | (unsigned int)cpu, slot);
	w->pft_len[cpu] = 0;
}

static void pft_bytes(PaWriter *w, int cpu, const unsigned char *b, unsigned int n)
{
	while (n--) {
		w->pft[cpu][w->pft_len[cpu]++] = *b++;
		if (w->pft_len[cpu] == 14)
			pft_emit_frame(w, cpu);
	}
}

void pa_pc_sample(PaWriter *w, int cpu, unsigned int pc)
{
	static const unsigned char async[6] = { 0, 0, 0, 0, 0, 0x80 };
	unsigned char isync[6];

	if (cpu < 0 || cpu >= PA_MAX_CPUS)
		return;
	if (!w->pft_synced[cpu]) {
		pft_bytes(w, cpu, async, 6);
		w->pft_synced[cpu] = 1;
	}
	/* I-sync: 08 | address LE (bit0 = Thumb) | info = 0x80 | reason Trace On (1) << 5 | NS << 3 */
	isync[0] = 0x08;
	put32(isync + 1, pc);
	isync[5] = 0x80 | (1 << 5) | (1 << 3);
	pft_bytes(w, cpu, isync, 6);
	w->samples++;
}

unsigned int pa_finish(PaWriter *w)
{
	int cpu;

	for (cpu = 0; cpu < PA_MAX_CPUS; cpu++)
		if (w->pft_len[cpu])
			pft_emit_frame(w, cpu);
	flush_pending(w);
	flush_frame(w);
	return w->len;
}
