/*
 * rrc_pa.h -- the contract between rrc_pa.skprx (kernel: process/thread/module
 * inspection and the CPU sampler behind Razor's CPU trace) and
 * retail_razorconnect.suprx (SceShell: speaks DBGP and PAMP to Target Manager).
 *
 * The kernel module is idle until rrcPaStart; it does nothing at boot beyond
 * allocating its buffers.
 */

#ifndef RRC_PA_H
#define RRC_PA_H

#define RRC_PA_VERSION          0x52504104u   /* "RPA" v4: + rrcPaReadMemory */

#define RRC_PA_STATE_IDLE       0
#define RRC_PA_STATE_CAPTURING  1
#define RRC_PA_STATE_STOPPED    2             /* trace encoded, readable with rrcPaRead */

/* rrcPaStart pc_mode */
#define RRC_PA_PC_NONE          0             /* scheduler timeline only */
#define RRC_PA_PC_REGISTERS     1             /* read the preempted thread's saved registers */

#define RRC_PA_MAX_THREADS      96
#define RRC_PA_MAX_MODULES      64
#define RRC_PA_READMEM_MAX      0x10000

typedef struct RrcPaInfo {
	unsigned int version;
	unsigned int state;              /* RRC_PA_STATE_* */
	unsigned int pid;
	unsigned int period_us;
	unsigned int cpu_mask;
	unsigned int records;            /* sampler records held */
	unsigned int records_dropped;    /* overwritten (wrap-around buffer) */
	unsigned int pc_samples;         /* records carrying a user PC */
	unsigned int reg_errors;         /* register reads that failed or had no user frame */
	int          last_reg_error;
	unsigned int ticks;              /* sampler wake-ups, all CPUs */
	int          last_error;         /* thread list / thread start errors */
	unsigned int encoded_bytes;      /* PA trace size after rrcPaStop */
	unsigned int intervals;          /* scheduler intervals encoded */
	unsigned int max_tick_us;        /* slowest single sample pass */
	unsigned int avg_tick_us;        /* mean sample pass */
	unsigned int threads_listed;     /* threads of the traced process at the last list refresh */
	unsigned int threads_eligible;   /* of those, summed over CPUs: affinity allows the core */
	unsigned int resume_errors;      /* debug-resume failures after a register read (should be 0) */
	unsigned int ring_capacity;      /* records the sampler keeps; older ones are dropped */
} RrcPaInfo;

/* 80 bytes */
typedef struct RrcPaThread {
	unsigned int tid;                /* user-visible thread id (PUID) */
	unsigned int status;             /* SceThreadStatus */
	int          priority;
	int          last_cpu;
	unsigned int entry;
	unsigned int stack;
	unsigned int stack_size;
	unsigned int attr;
	char         name[32];
	unsigned int run_us_lo;          /* runClocks, microseconds */
	unsigned int run_us_hi;
	unsigned int guid;               /* kernel UID */
	unsigned int reserved;
} RrcPaThread;

typedef struct RrcPaSegment {
	unsigned int perms;
	unsigned int vaddr;
	unsigned int memsz;
} RrcPaSegment;

/* 128 bytes */
typedef struct RrcPaModule {
	unsigned int modid;
	unsigned int state;
	char         name[28];
	char         path[48];
	RrcPaSegment seg[4];
} RrcPaModule;

/* Syscalls exported by rrc_pa.skprx, library RrcPa. Negative returns are errors. */
int rrcPaGetInfo(RrcPaInfo *info);
int rrcPaGetThreads(int pid, RrcPaThread *threads, int max);     /* returns count */
int rrcPaGetModules(int pid, RrcPaModule *modules, int max);     /* returns count; the main module first */
int rrcPaStart(int pid, unsigned int period_us, unsigned int cpu_mask, unsigned int pc_mode);
int rrcPaStop(void);                                              /* returns the trace size in bytes */
int rrcPaRead(unsigned int offset, void *buf, unsigned int len);  /* bytes copied, at most 0x10000; 0 = end */
int rrcPaReset(void);                                             /* free the trace, back to idle */
/* Copies len (<= RRC_PA_READMEM_MAX) bytes of process pid's memory at addr into buf; returns len. */
int rrcPaReadMemory(int pid, unsigned int addr, void *buf, unsigned int len);

#endif
