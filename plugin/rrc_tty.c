/*
 * rrc_tty.skprx  -- KERNEL half of retail_razorconnect: console capture
 *
 * What a DevKit shows in Console Output is the firmware's own debug output.
 * Every kernel printf and every user printf / sceClibPrintf ends up in two
 * sinks inside SceSysmem (SceDebugForKernel):
 *
 *   putchar handler  (ksceKernelRegisterDebugPutcharHandler)  one char at a time
 *   kprintf handler  (ksceKernelRegisterKprintfHandler)       fmt + va_list
 *
 * A retail kernel still routes output there -- there is simply nothing
 * registered on the other end. PrincessLog (net_logging_mgr.skprx) proves it
 * on this console: it captures ksceDebugPrintf, SceLibc printf and
 * sceClibPrintf through exactly these two registrations.
 *
 * This module registers both, tags each chunk with the stream, source,
 * process, thread and tick the TTYP header carries, and keeps the chunks in a
 * ring until the SceShell plugin drains them with rrcTtyRead(). Output from
 * before any tool connects stays in the ring, so boot logs are not lost.
 *
 * It does not send anything itself: kernel sockets cannot receive into module
 * memory on this firmware (see README), and the user plugin owns the session.
 *
 * The handlers run in whatever context printed -- any thread, possibly with
 * interrupts off -- so they only take a spinlock and never print or block.
 *
 * Firmware: links the 3.63+ SceDebugForKernel NIDs (the console is on 3.65).
 * On anything older the module fails to load cleanly with a missing-library
 * error, and the user plugin carries on without capture.
 *
 * Only one handler of each kind can be registered. Load this module after
 * net_logging_mgr.skprx (or remove that one): whichever registers last wins.
 */

#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>
#include <stdarg.h>

#include "rrc_tty.h"

#define RING_RECORDS    1024            /* x 128 bytes = 128 KiB */
#define READ_BATCH      32
#define KERNEL_PID      0x10005

/* A line still waiting for its newline is handed over once it is this old,
 * so a prompt without "\n" still shows up. The host keeps per-thread line
 * state, so a split line is reassembled on the PC. */
#define PARTIAL_AGE_US  100000

static SceKernelSpinlock g_lock;
static SceUID g_ring_blk = -1;
static RrcTtyRecord *g_ring;
static unsigned int g_head;             /* oldest closed record */
static unsigned int g_count;            /* closed records */
static int g_open;                      /* g_ring[g_head + g_count] is being filled */

static SceUID g_read_mtx = -1;
static RrcTtyRecord g_scratch[READ_BATCH];
static RrcTtyInfo g_info;

static RrcTtyRecord *slot_open(void)
{
	return &g_ring[(g_head + g_count) % RING_RECORDS];
}

static void close_record(void)
{
	if (g_open) {
		g_count++;
		g_open = 0;
	}
}

/* Called with g_lock held. One slot is always kept free for the open record;
 * when the ring is full the oldest closed record is dropped. */
static RrcTtyRecord *open_record(unsigned char stream, unsigned short source,
                                 unsigned int pid, unsigned int tid,
                                 unsigned long long tick)
{
	RrcTtyRecord *r;

	if (g_count >= RING_RECORDS - 1) {
		g_head = (g_head + 1) % RING_RECORDS;
		g_count--;
		g_info.records_dropped++;
	}
	r = slot_open();
	r->stream = stream;
	r->len = 0;
	r->source = source;
	r->pid = pid;
	r->tid = tid;
	r->tick_lo = (unsigned int)tick;
	r->tick_hi = (unsigned int)(tick >> 32);
	g_open = 1;
	return r;
}

static void push(unsigned char stream, unsigned short source, unsigned int pid,
                 const char *s, unsigned int n)
{
	unsigned int tid = (unsigned int)ksceKernelGetThreadId();
	unsigned long long tick = (unsigned long long)ksceKernelGetSystemTimeWide();
	SceKernelIntrStatus st;

	st = ksceKernelSpinlockLowLockCpuSuspendIntr(&g_lock);
	while (g_ring && n--) {
		char c = *s++;
		RrcTtyRecord *r = g_open ? slot_open() : 0;

		if (r && (r->stream != stream || r->pid != pid || r->tid != tid ||
		          r->len >= RRC_TTY_TEXT)) {
			close_record();
			r = 0;
		}
		if (!r)
			r = open_record(stream, source, pid, tid, tick);
		r->text[r->len++] = c;
		if (c == '\n')
			close_record();
	}
	ksceKernelSpinlockLowUnlockCpuResumeIntr(&g_lock, st);
}

/* User printf, sceClibPrintf and SceLibc stdout arrive here a character at a
 * time. Kernel threads can print through it too, so classify by process. */
static int putchar_handler(void *argp, char c)
{
	unsigned int pid = (unsigned int)ksceKernelGetProcessId();

	(void)argp;
	g_info.putchar_chars++;
	if (pid == KERNEL_PID)
		push(RRC_TTY_STREAM_KERNEL0, RRC_TTY_SOURCE_KERNEL, pid, &c, 1);
	else
		push(RRC_TTY_STREAM_STDOUT, RRC_TTY_SOURCE_USER, pid, &c, 1);
	return 0;
}

static int kprintf_handler(int unk, const char *fmt, va_list args)
{
	char buf[256];
	int n;

	(void)unk;
	g_info.kprintf_calls++;
	if (!fmt)
		return 0;
	n = vsnprintf(buf, sizeof(buf), fmt, args);
	if (n <= 0)
		return 0;
	if (n >= (int)sizeof(buf))
		n = sizeof(buf) - 1;
	push(RRC_TTY_STREAM_KERNEL0, RRC_TTY_SOURCE_KERNEL, KERNEL_PID, buf, (unsigned int)n);
	return 0;
}

/* ---------------------------------------------------------------- syscalls */

int rrcTtyGetInfo(RrcTtyInfo *info)
{
	int state, r;
	RrcTtyInfo snap;
	SceKernelIntrStatus st;

	ENTER_SYSCALL(state);
	st = ksceKernelSpinlockLowLockCpuSuspendIntr(&g_lock);
	g_info.records_pending = g_count;
	snap = g_info;
	ksceKernelSpinlockLowUnlockCpuResumeIntr(&g_lock, st);
	r = ksceKernelCopyToUser(info, &snap, sizeof(snap));
	EXIT_SYSCALL(state);
	return r < 0 ? r : 0;
}

int rrcTtyRead(RrcTtyRecord *records, int max_records)
{
	int state, n = 0, r = 0;
	SceKernelIntrStatus st;

	ENTER_SYSCALL(state);
	if (max_records <= 0) {
		EXIT_SYSCALL(state);
		return 0;
	}
	if (max_records > READ_BATCH)
		max_records = READ_BATCH;

	/* The copy to user memory can fault, so it cannot happen under the
	 * spinlock: records go to a scratch buffer first, and the mutex keeps
	 * two readers from sharing that buffer. */
	ksceKernelLockMutex(g_read_mtx, 1, 0);

	st = ksceKernelSpinlockLowLockCpuSuspendIntr(&g_lock);
	if (g_ring && g_open) {
		RrcTtyRecord *o = slot_open();
		unsigned long long born = ((unsigned long long)o->tick_hi << 32) | o->tick_lo;
		unsigned long long now = (unsigned long long)ksceKernelGetSystemTimeWide();

		if (o->len && now - born >= PARTIAL_AGE_US)
			close_record();
	}
	while (g_ring && n < max_records && g_count) {
		memcpy(&g_scratch[n], &g_ring[g_head], sizeof(RrcTtyRecord));
		g_head = (g_head + 1) % RING_RECORDS;
		g_count--;
		n++;
	}
	ksceKernelSpinlockLowUnlockCpuResumeIntr(&g_lock, st);

	if (n)
		r = ksceKernelCopyToUser(records, g_scratch, (SceSize)n * sizeof(RrcTtyRecord));

	ksceKernelUnlockMutex(g_read_mtx, 1);
	EXIT_SYSCALL(state);
	return r < 0 ? r : n;
}

/* ------------------------------------------------------------------ module */

void _start() __attribute__((weak, alias("module_start")));

int module_start(SceSize argc, const void *args)
{
	void *base = 0;

	(void)argc; (void)args;

	g_read_mtx = ksceKernelCreateMutex("rrc_tty_read", 0, 0, 0);
	if (g_read_mtx < 0)
		return SCE_KERNEL_START_FAILED;

	g_ring_blk = ksceKernelAllocMemBlock("rrc_tty_ring", SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW,
	                                     RING_RECORDS * sizeof(RrcTtyRecord), 0);
	if (g_ring_blk < 0 || ksceKernelGetMemBlockBase(g_ring_blk, &base) < 0) {
		if (g_ring_blk >= 0)
			ksceKernelFreeMemBlock(g_ring_blk);
		ksceKernelDeleteMutex(g_read_mtx);
		return SCE_KERNEL_START_FAILED;
	}
	memset(base, 0, RING_RECORDS * sizeof(RrcTtyRecord));
	g_ring = (RrcTtyRecord *)base;

	g_info.version = RRC_TTY_VERSION;
	g_info.putchar_result = ksceKernelRegisterDebugPutcharHandler(putchar_handler, 0);
	if (g_info.putchar_result >= 0)
		g_info.handlers |= RRC_TTY_HANDLER_PUTCHAR;
	g_info.kprintf_result = ksceKernelRegisterKprintfHandler(kprintf_handler, 0);
	if (g_info.kprintf_result >= 0)
		g_info.handlers |= RRC_TTY_HANDLER_KPRINTF;

	/* First line in the ring, and proof the kernel path works end to end. */
	ksceKernelPrintf("[rrc_tty] console capture active, handlers 0x%x\n", g_info.handlers);

	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
	SceKernelIntrStatus st;

	(void)argc; (void)args;

	ksceKernelRegisterKprintfHandler(0, 0);
	ksceKernelRegisterDebugPutcharHandler(0, 0);

	st = ksceKernelSpinlockLowLockCpuSuspendIntr(&g_lock);
	g_ring = 0;
	ksceKernelSpinlockLowUnlockCpuResumeIntr(&g_lock, st);

	ksceKernelLockMutex(g_read_mtx, 1, 0);
	ksceKernelFreeMemBlock(g_ring_blk);
	ksceKernelUnlockMutex(g_read_mtx, 1);
	ksceKernelDeleteMutex(g_read_mtx);
	return SCE_KERNEL_STOP_SUCCESS;
}
