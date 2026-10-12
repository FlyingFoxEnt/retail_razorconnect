/*
 * rrc_pa.skprx -- KERNEL half of Razor CPU trace support on a retail Vita.
 *
 * A DevKit feeds Razor from dedicated Performance Analysis hardware: CoreSight
 * program-flow trace plus scheduler "bookmarks" the kernel writes into a hardware
 * FIFO. Retail has neither, so this module samples in software and writes the same
 * buffer format (pa_encode.c).
 *
 * Sampling: one kernel thread per game core (0..2), pinned to that core, at a
 * priority above every user thread. Each wakes every period and, because it just
 * preempted whatever was running on its core, can read the state of the traced
 * process's threads without racing them:
 *   - every thread whose runClocks advanced and whose last CPU is this core ran
 *     here since the previous tick -> one record (thread, microseconds run);
 *   - the one still READY is the thread this wake-up preempted -> its saved user
 *     registers give the PC sample (Razor's "Function Sampling" histogram).
 * Only documented ThreadMgr exports are used; nothing is hooked or patched.
 *
 * rrcPaStop merges the records into per-core on-CPU intervals (switch in / switch
 * out packets) and PC samples (pa_trace.c). The PA trace is never held whole: rrcPaStop
 * only measures it, and rrcPaRead encodes the requested window into a fixed stage.
 * (It used to be encoded into one block of 128 bytes per record; with a full ring that
 * 4 MiB kernel allocation failed and Razor reported "Capture buffer is empty".)
 *
 * It also answers the SceShell plugin's DBGP needs that user mode cannot reach:
 * thread and module lists of another process.
 */

#include <psp2kern/kernel/cpu.h>
#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/sysclib.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/kernel/threadmgr.h>

#include "pa_trace.h"
#include "rrc_pa.h"

#define N_CPUS          4                       /* games run on 0..2; SceShell and the OS on 3 */
#define RING_RECORDS    32768
#define SAMPLER_PRIO    48                      /* above the user range (64..191) */
#define SAMPLER_STACK   0x4000
#define CPU_MASK(c)     (0x10000 << (c))

typedef PaRecord Record;

typedef struct ThreadCache {
	SceUID       guid;
	SceUID       puid;
	SceUInt64    run;
	unsigned int seen;                          /* tick generation, for eviction */
} ThreadCache;

static SceUID g_mtx = -1;                       /* start / stop / read / reset */
static SceKernelSpinlock g_ring_lock;
static SceUID g_ring_blk = -1;
static Record *g_ring;
static unsigned int g_head, g_count;

static SceUID g_stage_blk = -1;                 /* PA_TRACE_STAGE bytes: the read window */
static SceUID g_mem_blk = -1;                   /* bounce buffer for rrcPaReadMemory */
static unsigned char *g_mem;
static unsigned char *g_stage;
static PaTrace g_trace;                         /* static: syscalls run on a small kernel stack */
static int g_trace_ready;                       /* g_trace describes the stopped capture */
static unsigned int g_out_len;                  /* trace size, from the size pass */

static volatile int g_state = RRC_PA_STATE_IDLE;
static volatile int g_run;                      /* samplers should sample */
static SceUID g_pid;
static unsigned int g_period_us = 1000, g_cpu_mask, g_pc_mode;
static SceUID g_sema[N_CPUS] = { -1, -1, -1, -1 };
static SceUID g_thid[N_CPUS] = { -1, -1, -1, -1 };
static volatile int g_busy[N_CPUS];
static volatile int g_quit;
static int g_cpu_arg[N_CPUS] = { 0, 1, 2, 3 };

static RrcPaInfo g_info;
static SceUInt64 g_tick_us_total;
static unsigned int g_eligible[N_CPUS];

/* ---------------------------------------------------------------- ring */

static void ring_push(const Record *r)
{
	SceKernelIntrStatus st = ksceKernelSpinlockLowLockCpuSuspendIntr(&g_ring_lock);

	if (g_ring) {
		if (g_count == RING_RECORDS) {
			g_head = (g_head + 1) % RING_RECORDS;
			g_count--;
			g_info.records_dropped++;
		}
		memcpy(&g_ring[(g_head + g_count) % RING_RECORDS], r, sizeof(*r));
		g_count++;
		if (r->flags & PA_REC_HAS_PC)
			g_info.pc_samples++;
	}
	ksceKernelSpinlockLowUnlockCpuResumeIntr(&g_ring_lock, st);
}

/* ------------------------------------------------------------- sampling */

/* Debug suspend status used for the brief suspension below (valid mask 0xF7F03);
 * the same value hardware-tested retail debuggers use. */
#define PA_SUSPEND_STATUS 0x1002

static int user_pc(SceUID guid, unsigned int *pc)
{
	SceThreadCpuRegisters regs;
	int r, b;

	memset(&regs, 0, sizeof(regs));
	/* GetThreadCpuRegisters only answers for a suspended thread (0x80028030
	 * otherwise, even for a READY one). The thread was just preempted by this
	 * sampler, so suspending it takes effect at once; it is resumed immediately. */
	r = ksceKernelDebugSuspendThread(guid, PA_SUSPEND_STATUS);
	if (r < 0) {
		g_info.last_reg_error = r;
		return 0;
	}
	r = ksceKernelGetThreadCpuRegisters(guid, &regs);
	if (ksceKernelDebugResumeThread(guid, PA_SUSPEND_STATUS) < 0)
		g_info.resume_errors++;
	if (r < 0) {
		g_info.last_reg_error = r;
		return 0;
	}
	/* The two banks are current vs. saved-user; take the one in USR mode with a
	 * plausible PC and SP (a wrong pick reads PC = 0). */
	for (b = 0; b < 2; b++) {
		const SceArmCpuRegisters *e = &regs.entry[b];

		if ((e->cpsr & 0x1F) == 0x10 && e->pc && e->sp) {
			*pc = e->pc | ((e->cpsr & 0x20) ? 1u : 0u);
			return 1;
		}
	}
	g_info.last_reg_error = 1;
	return 0;
}

/* A thread may run on `cpu` if its affinity mask allows it. Masks come as the
 * 0x10000 << core form; 0 means "any". */
static int affinity_allows(int mask, int cpu)
{
	return mask == 0 || (mask & (0x10000 << cpu)) || (mask & (1 << cpu));
}

/* Rebuilds this core's cache from the traced process's thread list: only threads
 * whose affinity allows the core are kept, with their user id and a runClocks
 * baseline carried over from the previous cache when the thread was already known. */
static int refresh_threads(int cpu, ThreadCache *cache, int n_old)
{
	SceUID ids[RRC_PA_MAX_THREADS];
	ThreadCache keep[RRC_PA_MAX_THREADS];
	SceKernelThreadInfo info;
	int cnt = 0, i, j, n = 0;

	if (ksceKernelGetThreadIdList(g_pid, ids, RRC_PA_MAX_THREADS, &cnt) < 0) {
		g_info.last_error = -1;
		return 0;
	}
	if (cnt > RRC_PA_MAX_THREADS)
		cnt = RRC_PA_MAX_THREADS;
	g_info.threads_listed = (unsigned int)cnt;
	memcpy(keep, cache, (unsigned int)n_old * sizeof(ThreadCache));

	for (i = 0; i < cnt; i++) {
		memset(&info, 0, sizeof(info));
		info.size = sizeof(info);
		if (ksceKernelGetThreadInfo(ids[i], &info) < 0)
			continue;
		if (!affinity_allows(info.currentCpuAffinityMask, cpu))
			continue;
		cache[n].guid = ids[i];
		cache[n].run = (SceUInt64)-1;
		cache[n].puid = 0;
		for (j = 0; j < n_old; j++) {
			if (keep[j].guid == ids[i]) {
				cache[n].run = keep[j].run;
				cache[n].puid = keep[j].puid;
				break;
			}
		}
		if (cache[n].puid <= 0) {
			cache[n].puid = ksceKernelGetUserThreadId(ids[i]);
			if (cache[n].puid <= 0)
				cache[n].puid = ids[i];
		}
		n++;
	}
	return n;
}

#define LIST_REFRESH_TICKS 64

static void sample_once(int cpu, ThreadCache *cache, int *ncache, unsigned int gen)
{
	SceKernelThreadInfo info;
	Record recs[RRC_PA_MAX_THREADS];
	SceUInt64 now = (SceUInt64)ksceKernelGetSystemTimeWide();
	SceUInt64 done;
	int i, nrec = 0, preempted = -1;
	unsigned int best_run = 0;

	if (gen == 1 || (gen % LIST_REFRESH_TICKS) == 0) {
		*ncache = refresh_threads(cpu, cache, *ncache);
		g_eligible[cpu] = (unsigned int)*ncache;
	}

	for (i = 0; i < *ncache; i++) {
		ThreadCache *tc = &cache[i];
		SceUInt64 delta;

		memset(&info, 0, sizeof(info));
		info.size = sizeof(info);
		if (ksceKernelGetThreadInfo(tc->guid, &info) < 0)
			continue;
		tc->seen = gen;
		if (tc->run == (SceUInt64)-1 || info.runClocks < tc->run) {
			tc->run = info.runClocks;
			continue;
		}
		delta = info.runClocks - tc->run;
		tc->run = info.runClocks;
		if (delta == 0 || info.lastExecutedCpuId != cpu)
			continue;

		memset(&recs[nrec], 0, sizeof(Record));
		recs[nrec].t_lo = (unsigned int)now;
		recs[nrec].t_hi = (unsigned int)(now >> 32);
		recs[nrec].cpu = (unsigned char)cpu;
		recs[nrec].status = (unsigned char)info.status;
		recs[nrec].tid = (unsigned int)tc->puid;
		recs[nrec].run_us = delta > 0xFFFFFFFFull ? 0xFFFFFFFFu : (unsigned int)delta;
		recs[nrec].prio = info.currentPriority;
		/* The thread this wake-up preempted is READY; if several are, the one that
		 * ran longest is the best guess. */
		if (info.status == 2 /* SCE_THREAD_READY */ && recs[nrec].run_us >= best_run) {
			best_run = recs[nrec].run_us;
			preempted = nrec;
			recs[nrec].pc = (unsigned int)tc->guid;  /* guid until the PC is read */
		}
		nrec++;
	}

	for (i = 0; i < nrec; i++) {
		if (i == preempted) {
			SceUID guid = (SceUID)recs[i].pc;

			recs[i].pc = 0;
			if (g_pc_mode == RRC_PA_PC_REGISTERS) {
				if (user_pc(guid, &recs[i].pc))
					recs[i].flags |= PA_REC_HAS_PC;
				else
					g_info.reg_errors++;
			}
		} else {
			recs[i].pc = 0;
		}
		ring_push(&recs[i]);
	}

	done = (SceUInt64)ksceKernelGetSystemTimeWide() - now;
	if (done > g_info.max_tick_us)
		g_info.max_tick_us = (unsigned int)done;
	g_tick_us_total += done;
}

static int sampler_thread(SceSize args, void *argp)
{
	int cpu = *(int *)argp;
	ThreadCache *cache;
	SceUID blk;
	int ncache;
	unsigned int gen = 0;
	void *base = 0;

	(void)args;
	blk = ksceKernelAllocMemBlock("rrc_pa_cache", SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW,
	                              (RRC_PA_MAX_THREADS * sizeof(ThreadCache) + 0xFFF) & ~0xFFF, 0);
	if (blk < 0 || ksceKernelGetMemBlockBase(blk, &base) < 0)
		return ksceKernelExitDeleteThread(0);
	cache = (ThreadCache *)base;

	while (!g_quit) {
		ksceKernelWaitSema(g_sema[cpu], 1, 0);   /* idle until a capture starts */
		ncache = 0;
		while (g_run && !g_quit) {
			ksceKernelDelayThread(g_period_us);
			if (!g_run)
				break;
			g_busy[cpu] = 1;
			if (g_run)
				sample_once(cpu, cache, &ncache, ++gen);
			g_busy[cpu] = 0;
			g_info.ticks++;
		}
	}
	ksceKernelFreeMemBlock(blk);
	return ksceKernelExitDeleteThread(0);
}

/* ------------------------------------------------------------- encoding */

/* Sorts the records and measures the trace; rrcPaRead then encodes it window by window. */
static void encode_prepare(void)
{
	SceUID ids[1];
	SceUID tid = 0;
	int cnt = 0;

	pa_trace_sort(g_ring, RING_RECORDS, g_head, g_count);

	/* Razor abandons a CPU trace with no closed interval at all; when the records give
	 * none, pa_trace emits one short interval of a real thread (a made-up id 0 is
	 * rejected as a duplicate object). */
	if (ksceKernelGetThreadIdList(g_pid, ids, 1, &cnt) >= 0 && cnt > 0) {
		tid = ksceKernelGetUserThreadId(ids[0]);
		if (tid <= 0)
			tid = ids[0];
	}

	pa_trace_init(&g_trace, g_ring, RING_RECORDS, g_head, g_count, (unsigned int)g_pid,
	              g_period_us, (unsigned int)tid, g_stage, PA_TRACE_STAGE);
	g_out_len = pa_trace_size(&g_trace);
	g_info.intervals = g_trace.intervals;
	if (g_trace.overflow)
		g_info.last_error = -2;
	g_trace_ready = 1;
}

/* ---------------------------------------------------------------- syscalls */

int rrcPaGetInfo(RrcPaInfo *info)
{
	int state, r;
	RrcPaInfo snap;

	ENTER_SYSCALL(state);
	snap = g_info;
	snap.version = RRC_PA_VERSION;
	snap.state = (unsigned int)g_state;
	snap.records = g_count;
	snap.encoded_bytes = g_out_len;
	snap.avg_tick_us = snap.ticks ? (unsigned int)(g_tick_us_total / snap.ticks) : 0;
	snap.threads_eligible = g_eligible[0] + g_eligible[1] + g_eligible[2] + g_eligible[3];
	snap.ring_capacity = RING_RECORDS;
	r = ksceKernelCopyToUser(info, &snap, sizeof(snap));
	EXIT_SYSCALL(state);
	return r < 0 ? r : 0;
}

int rrcPaGetThreads(int pid, RrcPaThread *threads, int max)
{
	static SceUID ids[RRC_PA_MAX_THREADS];
	static RrcPaThread out[RRC_PA_MAX_THREADS];
	SceKernelThreadInfo info;
	int state, cnt = 0, i, n = 0, r;

	ENTER_SYSCALL(state);
	if (max > RRC_PA_MAX_THREADS)
		max = RRC_PA_MAX_THREADS;
	ksceKernelLockMutex(g_mtx, 1, 0);
	r = ksceKernelGetThreadIdList((SceUID)pid, ids, RRC_PA_MAX_THREADS, &cnt);
	if (r < 0) {
		ksceKernelUnlockMutex(g_mtx, 1);
		EXIT_SYSCALL(state);
		return r;
	}
	for (i = 0; i < cnt && n < max && i < RRC_PA_MAX_THREADS; i++) {
		SceUID puid;

		memset(&info, 0, sizeof(info));
		info.size = sizeof(info);
		if (ksceKernelGetThreadInfo(ids[i], &info) < 0)
			continue;
		memset(&out[n], 0, sizeof(out[n]));
		puid = ksceKernelGetUserThreadId(ids[i]);
		out[n].tid = (unsigned int)(puid > 0 ? puid : ids[i]);
		out[n].guid = (unsigned int)ids[i];
		out[n].status = info.status;
		out[n].priority = info.currentPriority;
		out[n].last_cpu = info.lastExecutedCpuId;
		out[n].entry = (unsigned int)info.entry;
		out[n].stack = (unsigned int)info.stack;
		out[n].stack_size = (unsigned int)info.stackSize;
		out[n].attr = info.attr;
		memcpy(out[n].name, info.name, sizeof(out[n].name));
		out[n].name[31] = 0;
		out[n].run_us_lo = (unsigned int)info.runClocks;
		out[n].run_us_hi = (unsigned int)(info.runClocks >> 32);
		n++;
	}
	r = n ? ksceKernelCopyToUser(threads, out, (SceSize)n * sizeof(RrcPaThread)) : 0;
	ksceKernelUnlockMutex(g_mtx, 1);
	EXIT_SYSCALL(state);
	return r < 0 ? r : n;
}

int rrcPaGetModules(int pid, RrcPaModule *modules, int max)
{
	static SceUID ids[RRC_PA_MAX_MODULES];
	static RrcPaModule out[RRC_PA_MAX_MODULES];
	static SceKernelModuleInfo info;
	SceSize num = RRC_PA_MAX_MODULES;
	SceUID main_mod;
	int state, i, n = 0, r, s;

	ENTER_SYSCALL(state);
	if (max > RRC_PA_MAX_MODULES)
		max = RRC_PA_MAX_MODULES;
	ksceKernelLockMutex(g_mtx, 1, 0);
	r = ksceKernelGetModuleList((SceUID)pid, 0xFF, 1, ids, &num);
	if (r < 0) {
		ksceKernelUnlockMutex(g_mtx, 1);
		EXIT_SYSCALL(state);
		return r;
	}
	if (num > RRC_PA_MAX_MODULES)
		num = RRC_PA_MAX_MODULES;
	/* Razor takes the first module as the executable (symbols, "pull the ELF"). The list
	 * comes newest first, which put the main module last (SceShell showed
	 * SceLiveAreaUtil as its executable), so move it to the front. */
	main_mod = ksceKernelGetModuleIdByPid((SceUID)pid);
	for (i = 1; main_mod >= 0 && i < (int)num; i++) {
		if (ids[i] == main_mod) {
			for (s = i; s > 0; s--)
				ids[s] = ids[s - 1];
			ids[0] = main_mod;
			break;
		}
	}
	for (i = 0; i < (int)num && n < max && i < RRC_PA_MAX_MODULES; i++) {
		memset(&info, 0, sizeof(info));
		info.size = sizeof(info);
		if (ksceKernelGetModuleInfo((SceUID)pid, ids[i], &info) < 0)
			continue;
		memset(&out[n], 0, sizeof(out[n]));
		out[n].modid = (unsigned int)ids[i];
		out[n].state = info.state;
		memcpy(out[n].name, info.module_name, sizeof(out[n].name));
		out[n].name[27] = 0;
		memcpy(out[n].path, info.path, sizeof(out[n].path));
		out[n].path[47] = 0;
		for (s = 0; s < 4; s++) {
			out[n].seg[s].perms = info.segments[s].perms;
			out[n].seg[s].vaddr = (unsigned int)info.segments[s].vaddr;
			out[n].seg[s].memsz = info.segments[s].memsz;
		}
		n++;
	}
	r = n ? ksceKernelCopyToUser(modules, out, (SceSize)n * sizeof(RrcPaModule)) : 0;
	ksceKernelUnlockMutex(g_mtx, 1);
	EXIT_SYSCALL(state);
	return r < 0 ? r : n;
}

static void stop_samplers(void)
{
	int c, tries;

	g_run = 0;
	for (tries = 0; tries < 400; tries++) {
		int busy = 0;

		for (c = 0; c < N_CPUS; c++)
			busy |= g_busy[c];
		if (!busy)
			break;
		ksceKernelDelayThread(1000);
	}
	ksceKernelDelayThread(g_period_us + 2000);   /* let the delay loops notice */
}

int rrcPaStart(int pid, unsigned int period_us, unsigned int cpu_mask, unsigned int pc_mode)
{
	int state, c;
	SceKernelIntrStatus st;

	ENTER_SYSCALL(state);
	ksceKernelLockMutex(g_mtx, 1, 0);
	if (g_state == RRC_PA_STATE_CAPTURING)
		stop_samplers();
	if (period_us < 500)
		period_us = 500;
	if (period_us > 100000)
		period_us = 100000;

	st = ksceKernelSpinlockLowLockCpuSuspendIntr(&g_ring_lock);
	g_head = g_count = 0;
	ksceKernelSpinlockLowUnlockCpuResumeIntr(&g_ring_lock, st);
	g_trace_ready = 0;
	g_out_len = 0;
	memset(&g_info, 0, sizeof(g_info));
	memset(g_eligible, 0, sizeof(g_eligible));
	g_tick_us_total = 0;
	g_pid = (SceUID)pid;
	g_period_us = period_us;
	g_cpu_mask = cpu_mask & ((1u << N_CPUS) - 1);
	g_pc_mode = pc_mode;
	g_info.pid = (unsigned int)pid;
	g_info.period_us = period_us;
	g_info.cpu_mask = g_cpu_mask;

	g_state = RRC_PA_STATE_CAPTURING;
	g_run = 1;
	for (c = 0; c < N_CPUS; c++)
		if ((g_cpu_mask & (1u << c)) && g_sema[c] >= 0)
			ksceKernelSignalSema(g_sema[c], 1);
	ksceKernelUnlockMutex(g_mtx, 1);
	EXIT_SYSCALL(state);
	return 0;
}

int rrcPaStop(void)
{
	int state, r;

	ENTER_SYSCALL(state);
	ksceKernelLockMutex(g_mtx, 1, 0);
	if (g_state == RRC_PA_STATE_CAPTURING) {
		stop_samplers();
		encode_prepare();
		g_state = RRC_PA_STATE_STOPPED;
	}
	r = (int)g_out_len;
	ksceKernelUnlockMutex(g_mtx, 1);
	EXIT_SYSCALL(state);
	return r;
}

/* Returns up to min(len, PA_TRACE_WINDOW) bytes; 0 only at the end of the trace. */
int rrcPaRead(unsigned int offset, void *buf, unsigned int len)
{
	int state, r = 0;

	ENTER_SYSCALL(state);
	ksceKernelLockMutex(g_mtx, 1, 0);
	if (g_trace_ready && g_state == RRC_PA_STATE_STOPPED && offset < g_out_len) {
		const unsigned char *data;
		unsigned int n = pa_trace_peek(&g_trace, offset, len, &data);

		if (n) {
			r = ksceKernelCopyToUser(buf, data, n);
			if (r >= 0)
				r = (int)n;
		}
	}
	ksceKernelUnlockMutex(g_mtx, 1);
	EXIT_SYSCALL(state);
	return r;
}

int rrcPaReset(void)
{
	int state;
	SceKernelIntrStatus st;

	ENTER_SYSCALL(state);
	ksceKernelLockMutex(g_mtx, 1, 0);
	if (g_state == RRC_PA_STATE_CAPTURING)
		stop_samplers();
	g_trace_ready = 0;
	g_out_len = 0;
	st = ksceKernelSpinlockLowLockCpuSuspendIntr(&g_ring_lock);
	g_head = g_count = 0;
	ksceKernelSpinlockLowUnlockCpuResumeIntr(&g_ring_lock, st);
	g_state = RRC_PA_STATE_IDLE;
	ksceKernelUnlockMutex(g_mtx, 1);
	EXIT_SYSCALL(state);
	return 0;
}

/* Razor reads the traced game's code (to fill the ELF's code sections before it will use the
 * symbols) and, for the GPU trace, HUD memory, over DBGP RDMEM. User mode cannot read another
 * process, so this copies through a kernel buffer. Read only; up to RRC_PA_READMEM_MAX bytes. */
int rrcPaReadMemory(int pid, unsigned int addr, void *buf, unsigned int len)
{
	int state, r;

	ENTER_SYSCALL(state);
	if (!g_mem || len == 0 || len > RRC_PA_READMEM_MAX || pid <= 0) {
		EXIT_SYSCALL(state);
		return -1;
	}
	ksceKernelLockMutex(g_mtx, 1, 0);
	r = ksceKernelCopyFromUserProc((SceUID)pid, g_mem, (const void *)addr, len);
	if (r >= 0)
		r = ksceKernelCopyToUser(buf, g_mem, len);
	ksceKernelUnlockMutex(g_mtx, 1);
	EXIT_SYSCALL(state);
	return r < 0 ? r : (int)len;
}

/* ------------------------------------------------------------------ module */

void _start() __attribute__((weak, alias("module_start")));

int module_start(SceSize argc, const void *args)
{
	void *base = 0;
	int c;

	(void)argc; (void)args;

	g_mtx = ksceKernelCreateMutex("rrc_pa", 0, 0, 0);
	if (g_mtx < 0)
		return SCE_KERNEL_START_FAILED;

	g_ring_blk = ksceKernelAllocMemBlock("rrc_pa_ring", SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW,
	                                     (RING_RECORDS * sizeof(Record) + 0xFFF) & ~0xFFF, 0);
	if (g_ring_blk < 0 || ksceKernelGetMemBlockBase(g_ring_blk, &base) < 0) {
		ksceKernelDeleteMutex(g_mtx);
		return SCE_KERNEL_START_FAILED;
	}
	g_ring = (Record *)base;

	g_stage_blk = ksceKernelAllocMemBlock("rrc_pa_stage", SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW,
	                                      (PA_TRACE_STAGE + 0xFFF) & ~0xFFF, 0);
	if (g_stage_blk < 0 || ksceKernelGetMemBlockBase(g_stage_blk, &base) < 0) {
		ksceKernelFreeMemBlock(g_ring_blk);
		ksceKernelDeleteMutex(g_mtx);
		return SCE_KERNEL_START_FAILED;
	}
	g_stage = (unsigned char *)base;

	/* optional: without it only memory reads fail */
	g_mem_blk = ksceKernelAllocMemBlock("rrc_pa_mem", SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW,
	                                    RRC_PA_READMEM_MAX, 0);
	if (g_mem_blk >= 0 && ksceKernelGetMemBlockBase(g_mem_blk, &base) >= 0)
		g_mem = (unsigned char *)base;

	for (c = 0; c < N_CPUS; c++) {
		g_sema[c] = ksceKernelCreateSema("rrc_pa_go", 0, 0, 1, 0);
		g_thid[c] = ksceKernelCreateThread("rrc_pa_sampler", sampler_thread, SAMPLER_PRIO,
		                                   SAMPLER_STACK, 0, CPU_MASK(c), 0);
		if (g_thid[c] >= 0)
			ksceKernelStartThread(g_thid[c], sizeof(int), &g_cpu_arg[c]);
		else
			g_info.last_error = g_thid[c];
	}
	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
	int c;

	(void)argc; (void)args;
	g_run = 0;
	g_quit = 1;
	for (c = 0; c < N_CPUS; c++)
		if (g_sema[c] >= 0)
			ksceKernelSignalSema(g_sema[c], 1);
	ksceKernelDelayThread(200 * 1000);
	return SCE_KERNEL_STOP_SUCCESS;
}
