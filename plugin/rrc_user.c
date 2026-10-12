/*
 * retail_razorconnect.suprx  -- USER-mode build
 *
 * Makes a retail PS Vita answer Sony's Target Manager / Neighborhood on
 * TCP+UDP 8540. Loaded by taiHEN into SceShell (*main in config.txt), which is
 * resident for the whole session and already has the network stack running.
 *
 * Why user mode: the kernel build got as far as accept() but every
 * ksceNetRecvfrom failed with 0xC0022005 (the net stack would not accept a
 * buffer in module .bss or on a stack), and the memory-block workaround
 * destabilised the console. User-mode sockets take ordinary buffers -- this is
 * the same approach VitaShell's FTP server and vitacompanion use.
 *
 * Protocol is a direct port of the proven PC mock (tools/mock16.py variant M).
 * See ../docs/PROTOCOL.md. Frame:
 *   u24 total_len | u8 0x40 | u16 flags | u16 node | u32 proto | u32 resv
 *   TSMP  (0x2000): u8 type, u8 code, u16 pad, u32 arg, u32 seq, body
 *   NETMP (0x1000): u8 code, u8 pad, u16 pad, body      (no arg/seq)
 *   CPUP  (0x3000): like TSMP with a single code byte
 *   TTYP  (0x800300NN): pushed console output, NN = stream
 *
 * Console Output is fed by rrc_tty.skprx (kernel), which captures the device's
 * real kernel and user printf output; this plugin drains it and pushes each
 * chunk as a TTYP frame. The kernel module is optional (weak import): without
 * it, only lines appended to ux0:data/rrc_console.txt are forwarded.
 *
 * Logging goes to ux0:data/rrc.log so it can be read over FTP.
 */

#include <psp2/kernel/clib.h>
#include <psp2/kernel/modulemgr.h>
#include <psp2/kernel/threadmgr.h>
#include <psp2/io/fcntl.h>
#include <psp2/net/net.h>
#include <psp2/net/netctl.h>
#include <psp2/sysmodule.h>
#include <psp2/kernel/processmgr.h>
#include <psp2/power.h>

#include <psp2/io/dirent.h>
#include <psp2/kernel/sysmem.h>

#include "rrc_tty.h"
#include "rrc_pa.h"
#include "pmon_trace.h"

#define PORT            8540
#define PROTO_NETMP     0x1000
#define PROTO_TSMP      0x2000
#define PROTO_CPUP      0x3000
#define PROTO_DBGP      0x20000       /* debugger: process/module/thread queries for Razor */
#define PROTO_PAMP      0x28000       /* performance analysis: Razor CPU trace (../docs/PAMP.md) */
#define PROTO_VCP       0x2b000       /* screen capture: Razor takes one per capture (../docs/VCP_FORMAT.md) */
#define MAXPAY          0x10800

/* Process enumeration for the Console Output GUI's per-process channels. All
 * user-mode: our own process is SceShell; the app list comes from SceAppMgr. */
extern int sceKernelGetProcessId(void);
extern int sceAppMgrGetPidListForShell(SceUID *pids, int max);
extern int sceAppMgrGetRunningAppIdListForShell(int *appIds, int count);   /* returns the count */
extern SceUID sceAppMgrGetProcessIdByAppIdForShell(int appId);
extern int sceKernelGetProcessTitleId(SceUID pid, char *titleid, unsigned int len);
extern int sceKernelGetProcessName(SceUID pid, char *name);

/* The console ID (IDPS, 16 bytes) names the target in Neighborhood. SceShell
 * reaches it through SceVshBridge; the buffer is 32 bytes as the NID expects. */
extern int _vshSblAimgrGetConsoleId(char CID[32]);
#define MARKER          0x40
#define HANDSHAKE_MAGIC 0x15A3F8E1
#define HWID            1444602

/* Each Sony tool holds its own session: Neighborhood keeps one open while
 * "Connected", and Console Output, Battery Monitor, Screen Capture etc. each
 * add another. Three slots ran out, which showed up as tools timing out and
 * new connections hanging in the backlog. */
#define MAX_CONN        8
#define RXBUF           2048
#define TXBUF           1024
#define UDPBUF          1024

#define LOGPATH "ux0:data/rrc.log"

/* ------------------------------------------------------------------ utils */

void *memset(void *d, int v, unsigned int n)
{
	unsigned char *p = (unsigned char *)d;
	while (n--)
		*p++ = (unsigned char)v;
	return d;
}

void *memcpy(void *d, const void *s, unsigned int n)
{
	unsigned char *a = (unsigned char *)d;
	const unsigned char *b = (const unsigned char *)s;
	while (n--)
		*a++ = *b++;
	return d;
}

void *memmove(void *d, const void *s, unsigned int n)
{
	unsigned char *a = (unsigned char *)d;
	const unsigned char *b = (const unsigned char *)s;

	if (a <= b || a >= b + n) {
		while (n--)
			*a++ = *b++;
	} else {
		a += n;
		b += n;
		while (n--)
			*--a = *--b;
	}
	return d;
}

unsigned int strlen(const char *s)
{
	unsigned int n = 0;
	while (s[n])
		n++;
	return n;
}

static void kmemset(void *d, int v, unsigned int n) { memset(d, v, n); }
static void kmemcpy(void *d, const void *s, unsigned int n) { memcpy(d, s, n); }
static unsigned int kstrlen(const char *s) { return strlen(s); }

static void put16(unsigned char *p, unsigned short v)
{
	p[0] = (unsigned char)(v & 0xff);
	p[1] = (unsigned char)(v >> 8);
}

static void put32(unsigned char *p, unsigned int v)
{
	p[0] = (unsigned char)(v & 0xff);
	p[1] = (unsigned char)((v >> 8) & 0xff);
	p[2] = (unsigned char)((v >> 16) & 0xff);
	p[3] = (unsigned char)((v >> 24) & 0xff);
}

static unsigned short get16(const unsigned char *p)
{
	return (unsigned short)(p[0] | (p[1] << 8));
}

static unsigned int get32(const unsigned char *p)
{
	return (unsigned int)p[0] | ((unsigned int)p[1] << 8) |
	       ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}

static unsigned short hton16(unsigned short v)
{
	return (unsigned short)((v >> 8) | (v << 8));
}

static unsigned int align4(unsigned int n) { return (n + 3u) & ~3u; }

/* ------------------------------------------------------------- log to file */

static void hex8(char *out, unsigned int v)
{
	static const char d[] = "0123456789ABCDEF";
	int i;

	for (i = 0; i < 8; i++)
		out[i] = d[(v >> ((7 - i) * 4)) & 0xf];
}

/* Append "msg <hex>\n" to the log file. Deliberately tiny: no printf. */
static void logline(const char *msg, unsigned int val, int with_val)
{
	char buf[160];
	unsigned int n = 0, l = kstrlen(msg);
	SceUID fd;

	if (l > 120)
		l = 120;
	kmemcpy(buf, msg, l);
	n = l;
	if (with_val) {
		buf[n++] = ' ';
		buf[n++] = '0';
		buf[n++] = 'x';
		hex8(buf + n, val);
		n += 8;
	}
	buf[n++] = '\n';

	fd = sceIoOpen(LOGPATH, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_APPEND, 0666);
	if (fd < 0)
		return;
	sceIoWrite(fd, buf, n);
	sceIoClose(fd);
}

#define LOG(m)        logline((m), 0, 0)
#define LOGV(m, v)    logline((m), (unsigned int)(v), 1)

/* ------------------------------------------------------- capture flag file
 *
 * Exists exactly while a Razor capture is running. A UE4 Development build polls it
 * (GXMGpuProfiler.cpp in the GXM RHI) and records per-scene GPU timing to
 * ux0:data/gxm_gpu_<unix time>.csv for as long as it exists. The file holds the traced
 * pid so a game can ignore a capture of another process.
 */
#define CAPTURE_FLAG_PATH "ux0:data/rrc_capturing"

static void capture_flag_set(unsigned int pid)
{
	char buf[16];
	SceUID fd = sceIoOpen(CAPTURE_FLAG_PATH, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0666);

	if (fd < 0) {
		logline("capture flag create failed", (unsigned int)fd, 1);
		return;
	}
	hex8(buf, pid);
	buf[8] = '\n';
	sceIoWrite(fd, buf, 9);
	sceIoClose(fd);
}

static void capture_flag_clear(void)
{
	sceIoRemove(CAPTURE_FLAG_PATH);
}

/* ---------------------------------------------------------- GPU trace source
 *
 * While the flag exists the game writes ux0:data/gxm_gpu_<unix time>.csv and ends it with a
 * "# end,frames,N" line once the flag is gone. At Stop the CSV that appeared during the capture
 * is converted by pmon_trace.c into the .pmon GPU trace Razor reads, keeping the last
 * GPU_TRACE_FRAMES frames (about 6 KB per frame for one scene per frame).
 */
#define GPU_CSV_DIR       "ux0:data"
#define GPU_TRACE_FRAMES  900
#define GPU_CSV_WAIT_MS   2000
#define GPU_BLOCK_SIZE    ((PMON_STAGE + PMON_HEAP_EVENTS * sizeof(PmonEvent) + \
                            PMON_LIVE_INTERVALS * sizeof(PmonLive) + 0xFFFu) & ~0xFFFu)

static PmonTrace g_gpu;
static SceUID g_gpu_blk = -1;
static int g_gpu_ready;                /* g_gpu describes the stopped capture's CSV */
static SceUID g_gpu_fd = -1;
static unsigned int g_gpu_csv_len;     /* the CSV as it was when converted */
static unsigned int g_gpu_csv_before;  /* newest CSV number when the capture started */
static char g_gpu_scan[512];

/* Number in "gxm_gpu_<number>.csv", 0 if the name is something else. */
static unsigned int gpu_csv_number(const char *name)
{
	static const char prefix[] = "gxm_gpu_";
	unsigned int i, n = 0, digits = 0;

	for (i = 0; prefix[i]; i++)
		if (name[i] != prefix[i])
			return 0;
	for (; name[i] >= '0' && name[i] <= '9'; i++, digits++)
		n = n * 10 + (unsigned int)(name[i] - '0');
	if (!digits || name[i] != '.' || name[i + 1] != 'c' || name[i + 2] != 's' ||
	    name[i + 3] != 'v' || name[i + 4] != 0)
		return 0;
	return n;
}

static unsigned int gpu_newest_csv(void)
{
	SceIoDirent e;
	SceUID d = sceIoDopen(GPU_CSV_DIR);
	unsigned int best = 0, n;

	if (d < 0)
		return 0;
	kmemset(&e, 0, sizeof(e));
	while (sceIoDread(d, &e) > 0) {
		n = gpu_csv_number(e.d_name);
		if (n > best)
			best = n;
		kmemset(&e, 0, sizeof(e));
	}
	sceIoDclose(d);
	return best;
}

static void gpu_csv_path(char *out, unsigned int number)
{
	static const char prefix[] = GPU_CSV_DIR "/gxm_gpu_";
	char digits[12];
	unsigned int n = 0, k = 0;

	kmemcpy(out, prefix, sizeof(prefix) - 1);
	n = sizeof(prefix) - 1;
	do {
		digits[k++] = (char)('0' + number % 10);
		number /= 10;
	} while (number);
	while (k)
		out[n++] = digits[--k];
	kmemcpy(out + n, ".csv", 5);
}

static int gpu_csv_read(void *ctx, unsigned int off, char *buf, unsigned int len)
{
	(void)ctx;
	if (g_gpu_fd < 0 || off >= g_gpu_csv_len)
		return 0;
	if (len > g_gpu_csv_len - off)
		len = g_gpu_csv_len - off;
	return sceIoPread(g_gpu_fd, buf, len, off);
}

/* Whether the CSV ends with the recorder's "# end," line; its size in *len. */
static int gpu_csv_complete(SceUID fd, unsigned int *len)
{
	char tail[48];
	SceOff size = sceIoLseek(fd, 0, SCE_SEEK_END);
	unsigned int n, i;

	*len = size > 0 ? (unsigned int)size : 0;
	if (*len < 8)
		return 0;
	n = *len < sizeof(tail) ? *len : sizeof(tail);
	if (sceIoPread(fd, tail, n, *len - n) != (int)n)
		return 0;
	for (i = 0; i + 6 <= n; i++)
		if (tail[i] == '#' && tail[i + 1] == ' ' && tail[i + 2] == 'e' && tail[i + 3] == 'n' &&
		    tail[i + 4] == 'd' && tail[i + 5] == ',')
			return 1;
	return 0;
}

static void gpu_reset(void)
{
	g_gpu_ready = 0;
	if (g_gpu_fd >= 0) {
		sceIoClose(g_gpu_fd);
		g_gpu_fd = -1;
	}
}

static void gpu_capture_start(void)
{
	gpu_reset();
	g_gpu_csv_before = gpu_newest_csv();
}

/* After Stop: find the capture's CSV, wait for the recorder to finish it, and measure the
 * trace. Returns the .pmon size, 0 when there is nothing to convert. */
static unsigned int gpu_capture_stop(unsigned int pid)
{
	char path[64];
	unsigned int number = 0, first = 0, last, waited;
	SceUInt64 t0;
	void *base = 0;
	int complete = 0;

	gpu_reset();
	for (waited = 0; waited <= GPU_CSV_WAIT_MS; waited += 100) {
		number = gpu_newest_csv();
		if (number > g_gpu_csv_before)
			break;
		number = 0;
		sceKernelDelayThread(100 * 1000);
	}
	if (!number) {
		LOG("gpu trace: the game wrote no GPU CSV during the capture (GPU profiler not in this build?)");
		return 0;
	}
	gpu_csv_path(path, number);
	g_gpu_fd = sceIoOpen(path, SCE_O_RDONLY, 0);
	if (g_gpu_fd < 0) {
		LOGV("gpu trace: cannot open the CSV", g_gpu_fd);
		return 0;
	}
	for (; waited <= GPU_CSV_WAIT_MS; waited += 100) {
		complete = gpu_csv_complete(g_gpu_fd, &g_gpu_csv_len);
		if (complete)
			break;
		sceKernelDelayThread(100 * 1000);
	}
	LOGV("gpu trace: CSV", number);
	LOGV("  bytes", g_gpu_csv_len);
	if (!complete)
		LOG("  the recorder had not finished it; using what was written");

	if (g_gpu_blk < 0) {
		g_gpu_blk = sceKernelAllocMemBlock("rrc_gpu_trace", SCE_KERNEL_MEMBLOCK_TYPE_USER_RW,
		                                   GPU_BLOCK_SIZE, 0);
		if (g_gpu_blk < 0 || sceKernelGetMemBlockBase(g_gpu_blk, &base) < 0) {
			LOGV("gpu trace: memory block failed", g_gpu_blk);
			if (g_gpu_blk >= 0)
				sceKernelFreeMemBlock(g_gpu_blk);
			g_gpu_blk = -1;
			gpu_reset();
			return 0;
		}
	} else {
		sceKernelGetMemBlockBase(g_gpu_blk, &base);
	}

	t0 = sceKernelGetProcessTimeWide();
	last = pmon_trace_last_frame(gpu_csv_read, 0, g_gpu_scan, sizeof(g_gpu_scan));
	if (last >= GPU_TRACE_FRAMES)
		first = last - GPU_TRACE_FRAMES + 1;
	pmon_trace_init(&g_gpu, gpu_csv_read, 0, pid, first,
	                (unsigned char *)base, PMON_STAGE,
	                (PmonEvent *)((unsigned char *)base + PMON_STAGE), PMON_HEAP_EVENTS,
	                (PmonLive *)((unsigned char *)base + PMON_STAGE + PMON_HEAP_EVENTS * sizeof(PmonEvent)),
	                PMON_LIVE_INTERVALS);
	pmon_trace_size(&g_gpu);
	g_gpu_ready = 1;
	LOGV("  pmon bytes", g_gpu.total);
	LOGV("  frames", g_gpu.stats.frames);
	LOGV("  first frame kept", first);
	LOGV("  scenes", g_gpu.stats.scenes);
	LOGV("  jobs", g_gpu.stats.jobs);
	LOGV("  samples", g_gpu.stats.samples);
	LOGV("  late events (should be 0)", g_gpu.stats.late_events);
	LOGV("  dropped intervals (should be 0)", g_gpu.stats.live_dropped);
	LOGV("  read error", (unsigned int)g_gpu.read_error);
	LOGV("  convert ms", (unsigned int)(sceKernelGetProcessTimeWide() - t0) / 1000u);
	return g_gpu.total;
}

/* Up to len bytes of the .pmon at off into buf; 0 at the end. */
static int gpu_trace_read(unsigned int off, unsigned char *buf, unsigned int len)
{
	const unsigned char *data;
	unsigned int n;

	if (!g_gpu_ready)
		return 0;
	n = pmon_trace_peek(&g_gpu, off, len, &data);
	if (n)
		kmemcpy(buf, data, n);
	return (int)n;
}

/* --------------------------------------------------------------- framing */

static int mkhdr(unsigned char *b, unsigned int paylen, unsigned short flags,
                 unsigned short node, unsigned int proto)
{
	unsigned int tot = 16 + paylen;

	b[0] = (unsigned char)(tot & 0xff);
	b[1] = (unsigned char)((tot >> 8) & 0xff);
	b[2] = (unsigned char)((tot >> 16) & 0xff);
	b[3] = MARKER;
	put16(b + 4, flags);
	put16(b + 6, node);
	put32(b + 8, proto);
	put32(b + 12, 0);
	return 16;
}

static unsigned int nv_record(unsigned char *out, const char *name,
                              const unsigned char *val, unsigned int vlen,
                              unsigned short vtype)
{
	unsigned int nlen = kstrlen(name) + 1;
	unsigned int npad = align4(nlen);
	unsigned int vpad = align4(vlen);
	unsigned int body = npad + 4 + vpad;
	unsigned int off = 0;

	put32(out + off, 8 + body); off += 4;
	put32(out + off, nlen);     off += 4;
	kmemcpy(out + off, name, nlen);
	kmemset(out + off + nlen, 0, npad - nlen);
	off += npad;
	put16(out + off, (unsigned short)vlen); off += 2;
	put16(out + off, vtype);                off += 2;
	kmemcpy(out + off, val, vlen);
	kmemset(out + off + vlen, 0, vpad - vlen);
	off += vpad;
	return off;
}

static int parse_keys(const unsigned char *body, unsigned int blen,
                      unsigned int *offs, unsigned int *lens, int maxk)
{
	unsigned int off = 4, count, i;
	int n = 0;

	if (blen < 4)
		return 0;
	count = get32(body);
	if (count > 64)
		count = 64;
	for (i = 0; i < count && n < maxk; i++) {
		unsigned int nlen;

		if (off + 4 > blen)
			break;
		nlen = get32(body + off);
		off += 4;
		if (nlen == 0 || off + nlen > blen)
			break;
		offs[n] = off;
		lens[n] = nlen;
		n++;
		off += align4(nlen);
	}
	return n;
}

/* -------------------------------------------------------- TSMP responses */

/* Everything the target reports about itself is read from the system at
 * runtime -- nothing here is hardcoded. sceKernelGetSystemSwVersion() gives
 * both the display string ("3.650.000") and the packed word psp2tm wants.
 * Note psp2tm renders the word as HEX digits, i.e. 3.650.000 is literally
 * 0x03650000, which is exactly what the system reports. */
static SceKernelSystemSwVersion g_sw;
static int g_sw_ok;

/* Pending Neighborhood power operation (ePowerOperation: 0 reboot, 0x80 power
 * off, 0x81 suspend), or 0xffffffff for none. POWER_STATUS reports the matching
 * transition until the status thread performs the real scePower* call. */
static volatile unsigned int g_power_op = 0xffffffffu;
static SceUInt64 g_power_at;

/* Console ID as 32 uppercase hex digits, or empty if it could not be read. */
static char g_idps[33];

static void read_device_info(void)
{
	static const char d[] = "0123456789ABCDEF";
	char cid[32];
	int i;

	kmemset(&g_sw, 0, sizeof(g_sw));
	g_sw.size = sizeof(g_sw);
	g_sw_ok = (sceKernelGetSystemSwVersion(&g_sw) >= 0);
	if (!g_sw_ok)
		g_sw.version = 0;

	kmemset(cid, 0, sizeof(cid));
	kmemset(g_idps, 0, sizeof(g_idps));
	if (_vshSblAimgrGetConsoleId(cid) >= 0) {
		for (i = 0; i < 16; i++) {
			g_idps[i * 2] = d[((unsigned char)cid[i] >> 4) & 0xf];
			g_idps[i * 2 + 1] = d[(unsigned char)cid[i] & 0xf];
		}
	}
}

static const char *fw_string(void)
{
	if (g_sw_ok && g_sw.versionString[0])
		return g_sw.versionString;
	return "unknown";
}

/* Neighborhood's Target column is the device's registry:/DEVENV/HOST/devkitname
 * setting. Report the console ID there; fall back to the firmware string (the
 * previous name) if the ID could not be read. */
#define SETTING_DEVKITNAME "registry:/DEVENV/HOST/devkitname"

static const char *target_name(void)
{
	return g_idps[0] ? g_idps : fw_string();
}

static int streq(const char *a, const char *b)
{
	while (*a && *a == *b) { a++; b++; }
	return *a == *b;
}

#define SDK_VERSION_WORD  (g_sw.version)

static unsigned int tsmp_body(unsigned char t, unsigned char c,
                              const unsigned char *body, unsigned int blen,
                              unsigned char *out)
{
	unsigned int off = 0;

	if (t == 1 && c == 0) {                       /* TARGET_LIST */
		put32(out + 0, 0);
		put16(out + 4, 1);
		put16(out + 6, 0);
		put32(out + 8, HWID);
		return 12;
	}
	if (t == 1 && c == 2) { put32(out, 0); return 4; }
	if (t == 2)           { put32(out, 0); return 4; }
	if (t == 3 && c == 0) {                       /* HW_INFO -> CPID */
		unsigned int offs[8], lens[8];
		unsigned char cpid[16];
		char name[64];
		int n, i;

		kmemset(cpid, 0, sizeof(cpid));
		put32(cpid + 0, HWID);
		put32(cpid + 4, 1);
		n = parse_keys(body, blen, offs, lens, 8);
		put32(out + 0, 0);
		put16(out + 4, (unsigned short)(n ? n : 1));
		put16(out + 6, 0);
		off = 8;
		if (n == 0)
			return off + nv_record(out + off, "CPID", cpid, 16, 1);
		for (i = 0; i < n; i++) {
			unsigned int l = lens[i] < sizeof(name) ? lens[i] : sizeof(name) - 1;

			kmemcpy(name, body + offs[i], l);
			name[l] = 0;
			off += nv_record(out + off, name, cpid, 16, 1);
		}
		return off;
	}
	if (t == 3 && c == 2) { put32(out + 0, 0); put32(out + 4, 0); return 8; }
	if (t == 3 && c == 4) {                       /* SW_INFO */
		unsigned int offs[8], lens[8];
		char name[64];
		int n, i;

		/* psp2tm (FUN_14008b9f0) requires value_type == 0 for SdkVersion and
		 * decodes the u32 as major = v>>24, minor = (v>>12)&0xfff,
		 * build = v&0xfff. A string here leaves the SDK column <Unknown>. */
		unsigned char ver[4];

		put32(ver, SDK_VERSION_WORD);
		n = parse_keys(body, blen, offs, lens, 8);
		put32(out + 0, 0);
		put16(out + 4, (unsigned short)(n ? n : 1));
		put16(out + 6, 0);
		off = 8;
		if (n == 0)
			return off + nv_record(out + off, "SdkVersion", ver, 4, 0);
		for (i = 0; i < n; i++) {
			unsigned int l = lens[i] < sizeof(name) ? lens[i] : sizeof(name) - 1;

			kmemcpy(name, body + offs[i], l);
			name[l] = 0;
			off += nv_record(out + off, name, ver, 4, 0);
		}
		return off;
	}
	if (t == 3 && c == 6) { put32(out + 0, 0); put32(out + 4, 0xFFFFFFFFu); return 8; }
	if (t == 3 && c == 8) {                       /* USB_INFO */
		kmemset(out, 0, 0x30);
		put32(out + 0, 0);
		put32(out + 4, 0x30 - 4);
		put32(out + 0x30, 8);
		put32(out + 0x34, 0);
		return 0x38;
	}
	if (t == 4 && c == 0) {                       /* POWER_STATUS */
		/* status word (2nd) is ePowerStatus: 0x100 ON, 1 NO_SUPPLY, 0 OFF,
		 * 0x200 SUSPENDED. While a power operation is pending, report the
		 * transition the host polls for (OFF for reboot/off, SUSPENDED for
		 * suspend); otherwise ON. NO_SUPPLY means a DevKit without power:
		 * Razor then refuses to capture ("Target power is unplugged"), so a
		 * handheld running on battery must still say ON. */
		unsigned int st;

		if (g_power_op == 0x81)
			st = 0x200;                       /* suspending */
		else if (g_power_op != 0xffffffffu)
			st = 0;                           /* rebooting / powering off */
		else
			st = 0x100;
		put32(out + 0, 0);
		put32(out + 4, st);
		return 8;
	}
	if (t == 4)           { put32(out, 0); return 4; }
	if (t == 5 && (c == 0 || c == 2)) {           /* GET_SETTINGS */
		unsigned int offs[8], lens[8];
		char name[128];
		int n, i;

		n = parse_keys(body, blen, offs, lens, 8);
		put32(out + 0, 0);
		put16(out + 4, (unsigned short)n);
		put16(out + 6, 0);
		off = 8;
		for (i = 0; i < n; i++) {
			unsigned int l = lens[i] < sizeof(name) ? lens[i] : sizeof(name) - 1;
			const char *val;

			kmemcpy(name, body + offs[i], l);
			name[l] = 0;
			val = streq(name, SETTING_DEVKITNAME) ? target_name() : fw_string();
			off += nv_record(out + off, name, (const unsigned char *)val,
			                 kstrlen(val) + 1, 2);
		}
		return off;
	}
	if (t == 5 && c == 8) {                       /* SETTINGS_XML */
		static const char xml[] = "<?xml version=\"1.0\"?><settings/>";

		put32(out + 0, 0);
		put32(out + 4, sizeof(xml));
		kmemcpy(out + 8, xml, sizeof(xml));
		kmemset(out + 8 + sizeof(xml), 0, align4(sizeof(xml)) - sizeof(xml));
		return 8 + align4(sizeof(xml));
	}
	put32(out, 0);
	return 4;
}

/* PROTO_LIST_RES descriptors: node must be non-zero or the entry is dropped.
 * Only advertise protocols we actually answer -- advertising one we ignore
 * makes the host wait on us. TTYP is included because the target PUSHES
 * console text on it; nothing is requested of us. */
#define PROTO_TTYP      0x80030000u          /* | stream, see rrc_tty.h */
#define PROTO_TTYP0     (PROTO_TTYP | RRC_TTY_STREAM_STDOUT)   /* user output */
#define PROTO_TTYPK     (PROTO_TTYP | RRC_TTY_STREAM_KERNEL0)  /* kernel output */
#define PROTO_PMEP      0x4000u              /* power monitor (Battery Monitor) */
/* One TTYP entry per stream we push: psp2tm derives the Console Output stream
 * from the protocol number, and user output and kernel output are separate.
 * DBGP is advertised so the Console Output GUI's GetProcessList succeeds and so
 * Razor can list modules and threads; PAMP and VCP carry Razor's CPU capture. */
/* DRFP (host0: file serving) is used the other way round: the plugin sends commands and
 * psp2tm answers (the virtual Razor HUD writes its .pmon); 0xa200 is psp2tm's own default node
 * for it (DRFP_FORMAT.md 2.1). */
#define PROTO_DRFP      0x11000u
#define DRFP_NODE       0xa200
#define N_PROTO 10
static const unsigned int g_pnum[N_PROTO] = {
	PROTO_NETMP, PROTO_TSMP, PROTO_CPUP, PROTO_TTYP0, PROTO_TTYPK, PROTO_PMEP, PROTO_DBGP,
	PROTO_PAMP, PROTO_VCP, PROTO_DRFP
};
static const unsigned short g_pnode[N_PROTO] = {
	0x0011, 0x0022, 0x0033, 0xa000, 0xa090, 0x0044, 0x0055, 0x0066, 0x0077, DRFP_NODE
};

static unsigned int netmp_body(unsigned char code, unsigned char *out,
                               unsigned char *rescode)
{
	unsigned int i, off;

	switch (code) {
	case 0:  *rescode = 1;  put32(out, 0); return 4;
	case 2:  *rescode = 3;  put32(out, 0); return 4;
	case 4:  *rescode = 5;  put32(out, 0); put32(out + 4, 0); return 8;
	case 6:  *rescode = 7;  put32(out, 0); put32(out + 4, 0); return 8;
	case 8:  *rescode = 9;  put32(out, 0); put32(out + 4, 0); return 8;
	case 10:
		*rescode = 11;
		put32(out + 0, 0);
		put32(out + 4, N_PROTO);
		off = 8;
		for (i = 0; i < N_PROTO; i++) {
			put32(out + off + 0, g_pnum[i]);
			put32(out + off + 4, MAXPAY);
			put32(out + off + 8, 0);
			put16(out + off + 12, g_pnode[i]);
			put16(out + off + 14, 0);
			off += 16;
		}
		return off;
	case 12: *rescode = 13; put32(out, 0); return 4;
	case 14: *rescode = 15; put32(out, 0); return 4;
	default: return 0;
	}
}

/* ---------------------------------------------------------- DBGP process list
 *
 * The Console Output GUI enumerates processes (GET_PROCESS_INFO, PROCESS group
 * 0x20 code 0x00) to build its per-process channels; without it the window
 * errors with TMAPI_COMMS_ERR_NO_CONNECT and shows nothing. Wire format solved
 * against psp2tm's decoder (see PROTOCOL.md):
 *   payload: 00 20 01 00 | u16 seq, u8 frag=0, u8 rsv | u32 result=0 | u32 count
 *            then packed entries, each self-sized by its first u32:
 *   entry: u32 size | u32 pid | u32 attrs | char name[36] | u32 affinity |
 *          u32 entry | u32 guid | u32 ppid | u32 0x14 | u32 sr[4] |
 *          u32 pathlen | char path[pad4(pathlen)] | u32 exidx[2],extab[2]
 * name is a fixed 36-byte NUL-terminated field; path is length-prefixed then
 * padded to 4. size must be >= 0x58 and cover the tail; sr size must be 0x14.
 */
static unsigned char g_dbg[0x10400];           /* 16-byte frame header + one DBGP payload */
static SceUID g_dbg_mtx = -1;                   /* g_dbg is shared by every session thread */
#define DBG_MAXPROC 24

/* eProcessAttr */
#define PROC_ATTR_LOADED      0x1
#define PROC_ATTR_SYSTEM      0x4
#define PROC_ATTR_DEBUGGABLE  0x10000
#define PROC_ATTR_ATTACHED    0x20000

/* Razor's CPU capture needs exactly one debuggable process; it is the foreground
 * application (the first non-SceShell pid). Attach only flips a flag: nothing on
 * the console is actually stopped. */
static volatile int g_attached_pid = -1;

static unsigned int cpstr(unsigned char *o, const char *s, unsigned int field)
{
	unsigned int i = 0;

	while (s[i] && i < field - 1) { o[i] = (unsigned char)s[i]; i++; }
	while (i < field) o[i++] = 0;
	return field;
}

static unsigned int dbg_entry(unsigned char *o, unsigned int pid,
                              const char *name, const char *path,
                              unsigned int guid, unsigned int ppid,
                              unsigned int attrs)
{
	unsigned int off = 4, pl, padded, i;

	put32(o + off, pid);        off += 4;
	put32(o + off, attrs);      off += 4;
	off += cpstr(o + off, name, 36);   /* +0x0c..+0x2f */
	put32(o + off, 0);          off += 4;   /* affinity */
	put32(o + off, 0);          off += 4;   /* entry */
	put32(o + off, guid);       off += 4;
	put32(o + off, ppid);       off += 4;
	put32(o + off, 0x14);       off += 4;   /* StopReason.size (required) */
	put32(o + off, 0);          off += 4;
	put32(o + off, 0);          off += 4;
	put32(o + off, 0);          off += 4;
	put32(o + off, 0);          off += 4;
	pl = 0; while (path[pl]) pl++; pl++;    /* include NUL */
	put32(o + off, pl);         off += 4;
	for (i = 0; i < pl; i++) o[off + i] = (unsigned char)path[i];
	padded = (pl + 3u) & ~3u;
	for (; i < padded; i++) o[off + i] = 0;
	off += padded;
	put32(o + off, 0); off += 4;            /* StartOfExidx */
	put32(o + off, 0); off += 4;            /* EndOfExidx */
	put32(o + off, 0); off += 4;            /* StartOfExtab */
	put32(o + off, 0); off += 4;            /* EndOfExtab */
	put32(o + 0, off);                      /* entry_size */
	return off;
}

static int pa_linked(void);

/* Name a pid: titleid first (e.g. "NPXS10015"), then the main module's name, then the
 * process name, then a synthetic label; the path is the main module's when rrc_pa can
 * list it. SceShell (our own process) is named explicitly. name holds 40 bytes, path 48. */
static void proc_name(SceUID pid, SceUID self, char *name, char *path)
{
	char tid[0x20];
	RrcPaModule mod;
	int i, have_mod;

	name[0] = 0; path[0] = 0;
	if (pid == self) {
		kmemcpy(name, "SceShell", 9);
		kmemcpy(path, "vs0:vsh/shell/eboot.bin", 24);
		return;
	}
	kmemset(tid, 0, sizeof(tid));
	kmemset(&mod, 0, sizeof(mod));
	/* rrc_pa lists the main module first: its path is the executable Razor asks for. */
	have_mod = pa_linked() && rrcPaGetModules((int)pid, &mod, 1) == 1 && mod.name[0];
	if (have_mod) {
		mod.path[sizeof(mod.path) - 1] = 0;
		kmemcpy(path, mod.path, sizeof(mod.path));
	}
	if (sceKernelGetProcessTitleId(pid, tid, sizeof(tid)) >= 0 && tid[0]) {
		for (i = 0; tid[i] && i < 31; i++) name[i] = tid[i];
		name[i] = 0;
		if (!have_mod) {
			kmemcpy(path, "ux0:app/", 8);
			for (i = 0; tid[i] && i < 24; i++) path[8 + i] = tid[i];
			path[8 + i] = 0;
		}
		return;
	}
	if (have_mod) {
		mod.name[sizeof(mod.name) - 1] = 0;
		kmemcpy(name, mod.name, sizeof(mod.name));
		return;
	}
	if (sceKernelGetProcessName(pid, name) >= 0 && name[0])
		return;
	kmemcpy(name, "process", 8);
}

/* System applications run from vs0: (or os0:); a game or homebrew from ux0:/app0:/gro0:.
 * The main module's path comes from rrc_pa; the title id of another process cannot be read
 * from here (VitaShell was named by its module, 17/09), so that is only the fallback. */
static int is_system_app(SceUID pid)
{
	char tid[0x20];
	RrcPaModule mod;

	kmemset(&mod, 0, sizeof(mod));
	if (pa_linked() && rrcPaGetModules((int)pid, &mod, 1) == 1 && mod.path[0])
		return (mod.path[0] == 'v' && mod.path[1] == 's' && mod.path[2] == '0') ||
		       (mod.path[0] == 'o' && mod.path[1] == 's' && mod.path[2] == '0');
	kmemset(tid, 0, sizeof(tid));
	if (sceKernelGetProcessTitleId(pid, tid, sizeof(tid)) < 0 || !tid[0])
		return 1;
	return tid[0] == 'N' && tid[1] == 'P' && tid[2] == 'X' && tid[3] == 'S';
}

static void add_pid(SceUID *out, int *n, int max, SceUID pid, SceUID self)
{
	int i;

	if (pid <= 0 || pid == self || *n >= max)
		return;
	for (i = 0; i < *n; i++)
		if (out[i] == pid)
			return;
	out[(*n)++] = pid;
}

/* Whether `pid` still exists. rrc_pa lists its threads from the kernel (fails for a dead
 * pid); without rrc_pa, whether its title id can be read. */
static int process_alive(SceUID pid, char *tid, unsigned int tidlen)
{
	RrcPaThread one;

	if (pa_linked())
		return rrcPaGetThreads((int)pid, &one, 1) >= 0;
	return sceKernelGetProcessTitleId(pid, tid, tidlen) >= 0;
}

/* Processes seen printing: rrc_tty tags every console chunk with its pid, and a UE4 game
 * prints from its first second. Until 17/09 the plugin asked SceAppMgr for 24 entries, which
 * fails with 0x8002710B (SCE_KERNEL_ERROR_NO_MEMORY; 20 works), so no game was ever listed;
 * this stays as a second source. */
#define SEEN_MAX 8
static SceUID g_seen_pid[SEEN_MAX];
static SceUInt64 g_seen_at[SEEN_MAX];

static void note_pid(SceUID pid)
{
	SceUID self = sceKernelGetProcessId();
	SceUInt64 now = sceKernelGetProcessTimeWide();
	int i, slot = 0;

	if (pid <= 0 || pid == self)
		return;
	for (i = 0; i < SEEN_MAX; i++) {
		if (g_seen_pid[i] == pid) {
			g_seen_at[i] = now;
			return;
		}
		if (g_seen_at[i] < g_seen_at[slot])
			slot = i;
	}
	g_seen_pid[slot] = pid;
	g_seen_at[slot] = now;
}

/* Which buffer size the two SceAppMgr lists accept, found once per boot by trying several
 * (a size that is too small may be what NO_MEMORY means); 0 = none worked. */
static int g_appmgr_ids_count = -1, g_appmgr_pids_count = -1;
static int g_appmgr_ids[256];
static SceUID g_appmgr_pids[256];

static void appmgr_probe(void)
{
	static const int counts[] = { 1, 8, 16, 20, 24, 32, 64, 128, 256 };
	unsigned int i;

	g_appmgr_ids_count = 0;
	g_appmgr_pids_count = 0;
	for (i = 0; i < sizeof(counts) / sizeof(counts[0]); i++) {
		int a = sceAppMgrGetRunningAppIdListForShell(g_appmgr_ids, counts[i]);
		int b = sceAppMgrGetPidListForShell(g_appmgr_pids, counts[i]);

		LOGV("appmgr probe: count", counts[i]);
		LOGV("  running app ids ->", (unsigned int)a);
		LOGV("  shell pid list ->", (unsigned int)b);
		/* 17/09 on 3.74: sizes up to 20 work, 24 and more fail; keep the largest that works */
		if (a >= 0)
			g_appmgr_ids_count = counts[i];
		if (b >= 0)
			g_appmgr_pids_count = counts[i];
	}
}

/* Running application processes, a game before system apps (NPXS...). Sources: the two
 * SceAppMgr lists (when the probe found a size they accept) and the processes seen
 * printing. The result is logged whenever it changes. */
static int app_pids(SceUID self, SceUID *out, int max)
{
	static int last_a = -1000, last_b = -1000;
	static SceUID last_first;
	SceUID tmp[DBG_MAXPROC];
	int a = -1, b = -1, i, n = 0, k = 0;

	if (g_appmgr_ids_count < 0)
		appmgr_probe();
	if (g_appmgr_ids_count > 0) {
		a = sceAppMgrGetRunningAppIdListForShell(g_appmgr_ids, g_appmgr_ids_count);
		for (i = 0; i < a && i < g_appmgr_ids_count; i++)
			add_pid(tmp, &n, DBG_MAXPROC, sceAppMgrGetProcessIdByAppIdForShell(g_appmgr_ids[i]), self);
	}
	if (g_appmgr_pids_count > 0) {
		b = sceAppMgrGetPidListForShell(g_appmgr_pids, g_appmgr_pids_count);
		for (i = 0; i < b && i < g_appmgr_pids_count; i++)
			add_pid(tmp, &n, DBG_MAXPROC, g_appmgr_pids[i], self);
	}
	{
		char tid[0x20];
		int j, best;
		unsigned int used = 0;

		/* seen printing, most recent first, while the process still exists */
		for (j = 0; j < SEEN_MAX; j++) {
			best = -1;
			for (i = 0; i < SEEN_MAX; i++)
				if (g_seen_pid[i] > 0 && !(used & (1u << i)) &&
				    (best < 0 || g_seen_at[i] > g_seen_at[best]))
					best = i;
			if (best < 0)
				break;
			used |= 1u << best;
			if (!process_alive(g_seen_pid[best], tid, sizeof(tid))) {
				g_seen_pid[best] = 0;           /* exited */
				continue;
			}
			add_pid(tmp, &n, DBG_MAXPROC, g_seen_pid[best], self);
		}
	}

	for (i = 0; i < n && k < max; i++)          /* games first, order otherwise kept */
		if (!is_system_app(tmp[i]))
			out[k++] = tmp[i];
	for (i = 0; i < n && k < max; i++)
		if (is_system_app(tmp[i]))
			out[k++] = tmp[i];

	if (a != last_a || b != last_b || (k ? out[0] : 0) != last_first) {
		last_a = a;
		last_b = b;
		last_first = k ? out[0] : 0;
		LOGV("proc list: running app ids", (unsigned int)a);
		LOGV("proc list: shell pid list", (unsigned int)b);
		for (i = 0; i < k; i++) {
			char tid[0x20];

			kmemset(tid, 0, sizeof(tid));
			sceKernelGetProcessTitleId(out[i], tid, sizeof(tid));
			tid[sizeof(tid) - 1] = 0;
			LOGV(i ? "  app pid" : "  app pid (debuggable)", out[i]);
			if (tid[0])
				LOG(tid);
		}
	}
	return k;
}

/* The process Razor is offered as debuggable: the first running app, else SceShell. */
static unsigned int debuggable_pid(void)
{
	SceUID self = sceKernelGetProcessId();
	SceUID pids[DBG_MAXPROC];

	return app_pids(self, pids, DBG_MAXPROC - 1) > 0 ? (unsigned int)pids[0] : (unsigned int)self;
}

/* Build the whole GET_PROCESS_INFO response payload into g_dbg+16 (leaving room
 * for the 16-byte frame header) and return the payload length. */
static unsigned int dbgp_procinfo(void)
{
	unsigned char *p = g_dbg + 16;
	SceUID self = sceKernelGetProcessId();
	SceUID pids[DBG_MAXPROC];
	int cnt, i;
	unsigned int off = 16, n = 0;
	char name[40], path[48];

	p[0] = 0x00; p[1] = 0x20; p[2] = 0x01; p[3] = 0x00;
	put16(p + 4, 0); p[6] = 0; p[7] = 0;
	put32(p + 8, 0);                        /* result = 0 */

	/* SceShell first (the process most console output comes from). */
	proc_name(self, self, name, path);
	off += dbg_entry(p + off, (unsigned int)self, name, path, 0, 0, PROC_ATTR_LOADED);
	n++;

	cnt = app_pids(self, pids, DBG_MAXPROC - 1);
	for (i = 0; i < cnt && n < DBG_MAXPROC; i++) {
		unsigned int attrs = PROC_ATTR_LOADED;

		if (off + 0x120 > sizeof(g_dbg))
			break;
		if (n == 1) {                       /* the foreground app: a game when one runs */
			attrs |= PROC_ATTR_DEBUGGABLE;
			if (pids[i] == g_attached_pid)
				attrs |= PROC_ATTR_ATTACHED;
		}
		proc_name(pids[i], self, name, path);
		off += dbg_entry(p + off, (unsigned int)pids[i], name, path, 0, 0, attrs);
		n++;
	}
	/* No application running: offer SceShell itself, so a capture still works
	 * (entry 0 starts at payload +16; its attrs word is at +8). */
	if (n == 1) {
		unsigned int attrs = PROC_ATTR_LOADED | PROC_ATTR_DEBUGGABLE;

		if (self == g_attached_pid)
			attrs |= PROC_ATTR_ATTACHED;
		put32(p + 16 + 8, attrs);
	}
	put32(p + 12, n);
	return off;
}

/* ------------------------------------------------- DBGP for Razor (rrc_pa)
 *
 * Layouts: ../docs/DBGP_MODULE_THREAD_FORMAT.md. Every reply starts with
 *   b0 | group | code+1 | 0 | u16 seq=0 | u8 frag=0 | u8 0 | u32 result
 * A header with a nonzero result is a valid, immediate refusal; without any reply
 * psp2tm waits 5 s. Module and thread data of another process come from
 * rrc_pa.skprx (weak import, checked before use like rrc_tty).
 */
#define DBGP_UNSUPPORTED 8

static RrcPaModule g_pa_mods[RRC_PA_MAX_MODULES];
static RrcPaThread g_pa_threads[RRC_PA_MAX_THREADS];

static unsigned int g_pa_version;             /* what rrc_pa.skprx reported, 0 = not loaded */

static int pa_linked(void)
{
	const unsigned int *stub = (const unsigned int *)((unsigned int)&rrcPaGetInfo & ~1u);
	RrcPaInfo info;

	if ((stub[0] & 0xf0000000u) != 0xe0000000u)
		return 0;
	kmemset(&info, 0, sizeof(info));
	if (rrcPaGetInfo(&info) < 0)
		return 0;
	g_pa_version = info.version;
	return info.version == RRC_PA_VERSION;
}

static unsigned int dbgp_hdr(unsigned char *p, const unsigned char *req, unsigned int result)
{
	p[0] = req[0]; p[1] = req[1]; p[2] = (unsigned char)(req[2] | 1); p[3] = 0;
	put16(p + 4, 0); p[6] = 0; p[7] = 0;
	put32(p + 8, result);
	return 12;
}

/* ------------------------------------------------- Razor HUD impersonation
 *
 * Razor's GPU Trace does not use PAMP: it looks for the DevKit HUD library (module
 * "SceRazorHud") in the traced process, reads its executable segment for the marker
 * B0 BE BA BE FE BE 77 BE + info-struct address, reads the 0x20-byte info struct (version 1,
 * size 0x20, trace-completion breakpoint, command buffer), writes a 0x204-byte command
 * (1 arm, 2 stop, 4 teardown), sets a software breakpoint on the completion address and waits
 * for the process to stop there; then it loads the .pmon the HUD wrote to host0:.
 * (../docs/GPU_TRACE_SESSION.md.) A retail console has no HUD, so the plugin lists a virtual one:
 * a 4 KB region that exists only in these DBGP replies.
 */
#define HUD_BASE          0x7E000000u
#define HUD_SIZE          0x1000u
#define HUD_MARKER_OFF    0x40u
#define HUD_INFO_OFF      0x80u
#define HUD_BP_OFF        0x100u
#define HUD_CMD_OFF       0x200u
#define HUD_CMD_SIZE      0x204u
#define HUD_MODID         0x7EADB0D1u
/* Listed only once the whole exchange works: Razor may also start the HUD trace next to a
 * CPU capture, and a HUD that cannot finish would fail that capture. */
#define HUD_ENABLED       1

static unsigned char g_hud[HUD_SIZE];
static int g_hud_ready;

static void hud_init(void)
{
	static const unsigned char marker[8] = { 0xB0, 0xBE, 0xBA, 0xBE, 0xFE, 0xBE, 0x77, 0xBE };
	unsigned char *info = g_hud + HUD_INFO_OFF;

	if (g_hud_ready)
		return;
	kmemset(g_hud, 0, sizeof(g_hud));
	kmemcpy(g_hud + HUD_MARKER_OFF, marker, 8);
	put32(g_hud + HUD_MARKER_OFF + 8, HUD_BASE + HUD_INFO_OFF);
	put32(info + 0x00, 1);                              /* version */
	put32(info + 0x04, 0x20);                           /* size */
	put32(info + 0x0c, HUD_BASE + HUD_BP_OFF);          /* trace completion breakpoint */
	put32(info + 0x10, HUD_BASE + HUD_CMD_OFF);         /* command buffer */
	/* the "code" at the breakpoint: Thumb NOPs, in case anything reads it */
	put16(g_hud + HUD_BP_OFF, 0xBF00);
	put16(g_hud + HUD_BP_OFF + 2, 0xBF00);
	g_hud_ready = 1;
}

static int hud_contains(unsigned int addr, unsigned int len)
{
	return addr >= HUD_BASE && len <= HUD_SIZE && addr - HUD_BASE <= HUD_SIZE - len;
}

/* The HUD's work, done here instead: record while armed (until Razor's stop command or
 * HUD_TRACE_MS), convert the game's CSV, write the .pmon to host0:, then report the process
 * stopped at the completion breakpoint. */
/* Razor's GPU-trace session waits only ~8 s after it resumes the process for the completion
 * breakpoint ("Target is unavailable" otherwise), so the whole record + convert + host0 write
 * has to finish inside that. Record a short fixed window (plenty of frames) rather than the
 * trace_size Razor asks for. */
#define HUD_TRACE_MS      2500u

static SceUID g_hud_thid = -1;
static volatile int g_hud_busy;
static volatile int g_hud_stop_req;
static unsigned int g_hud_pid;
static char g_hud_arg[0x200];

static int hud_finish(unsigned int pid, unsigned int total);   /* host0: write + stop event */
static void hud_read_settings(int sock);                        /* tmp_settings.ini via host0: */
static unsigned int g_hud_trace_ms = HUD_TRACE_MS;

static volatile int g_dbgp_sock = -1;  /* session of the last DBGP request, and its header */
static unsigned short g_dbgp_flags, g_dbgp_node;
static int g_hud_sock = -1;            /* the session that armed the HUD */
static unsigned short g_hud_flags, g_hud_node;
static unsigned int g_hud_bp_id;       /* software breakpoint Razor set on the completion address */

static int hud_thread(SceSize args, void *argp)
{
	unsigned int waited = 0, total;

	(void)args; (void)argp;
	hud_read_settings(g_hud_sock);
	gpu_capture_start();
	capture_flag_set(g_hud_pid);
	LOGV("hud: recording, pid", g_hud_pid);
	while (!g_hud_stop_req && waited < g_hud_trace_ms) {
		sceKernelDelayThread(50 * 1000);
		waited += 50;
	}
	capture_flag_clear();
	LOGV("hud: recorded ms", waited);
	total = gpu_capture_stop(g_hud_pid);
	hud_finish(g_hud_pid, total);
	g_hud_busy = 0;
	return sceKernelExitDeleteThread(0);
}

static void hud_command(unsigned int pid, const unsigned char *cmd, unsigned int len)
{
	unsigned int c = len >= 4 ? get32(cmd) : 0, i;

	for (i = 0; i + 4 < len && i < sizeof(g_hud_arg) - 1 && cmd[4 + i]; i++)
		g_hud_arg[i] = (char)cmd[4 + i];
	g_hud_arg[i] = 0;
	LOGV("hud command", c);
	LOGV("  pid", pid);
	if (g_hud_arg[0])
		LOG(g_hud_arg);
	if (c == 1) {                           /* arm: start a trace */
		if (g_hud_busy) {
			LOG("  a trace is already running");
			return;
		}
		g_hud_pid = pid;
		g_hud_sock = g_dbgp_sock;
		g_hud_flags = g_dbgp_flags;
		g_hud_node = g_dbgp_node;
		g_hud_stop_req = 0;
		g_hud_busy = 1;
		/* below the session threads (0x40): the conversion is CPU work */
		g_hud_thid = sceKernelCreateThread("rrc_hud", hud_thread, 0xA0, 0x4000, 0, 0, 0);
		if (g_hud_thid < 0 || sceKernelStartThread(g_hud_thid, 0, 0) < 0) {
			LOGV("  hud thread failed", g_hud_thid);
			g_hud_busy = 0;
		}
	} else if (c == 2 || c == 4) {          /* stop / teardown */
		g_hud_stop_req = 1;
	}
}

/* One more GET_MOD_INFO entry: the virtual HUD. */
static unsigned int hud_module_entry(unsigned char *p, unsigned int off)
{
	unsigned int e = off;

	hud_init();
	kmemset(p + e, 0, 0x50);
	put32(p + e + 0x04, HUD_MODID);
	p[e + 0x10] = 0x20;                                     /* PRX */
	put32(p + e + 0x18, 1);
	cpstr(p + e + 0x24, "SceRazorHud", 26);
	put32(p + e + 0x44, 2);                                 /* LIVE */
	put32(p + e + 0x4c, 1);
	off = e + 0x50;
	put32(p + off, 0x14);
	put32(p + off + 4, 0x5);                                /* R-X: Razor scans attr & 1 */
	put32(p + off + 8, HUD_BASE);
	put32(p + off + 12, HUD_SIZE);
	put32(p + off + 16, 4);
	off += 0x14;
	kmemset(p + off, 0, 16);
	off += 16;
	put32(p + e, off - e);
	return off;
}

/* GET_MOD_INFO_RES: pid | count | entries (size, id, sdk, u16 ver, u16 0, u8 type, u8 0,
 * u16 flags, start, refcnt, stop, exit, name[32], status, guid, nseg, nseg*0x14, exidx/extab). */
static unsigned int dbgp_modules(unsigned char *p, unsigned int off, unsigned int pid)
{
	int n = pa_linked() ? rrcPaGetModules((int)pid, g_pa_mods, RRC_PA_MAX_MODULES) : 0;
	int i, s;
	unsigned int cnt = 0, cntoff;

	put32(p + off, pid); off += 4;
	cntoff = off; off += 4;
	for (i = 0; i < n; i++) {
		unsigned int e = off, nseg = 0;

		if (off + 0x100 > sizeof(g_dbg) - 16)
			break;
		kmemset(p + e, 0, 0x50);
		put32(p + e + 0x04, g_pa_mods[i].modid);
		p[e + 0x10] = (i == 0) ? 0x10 : 0x20;              /* fixed ELF main module, then PRX */
		put32(p + e + 0x18, 1);                              /* reference count */
		cpstr(p + e + 0x24, g_pa_mods[i].name, 26);
		put32(p + e + 0x44, 2);                              /* LIVE */
		off = e + 0x50;
		for (s = 0; s < 4; s++) {
			if (!g_pa_mods[i].seg[s].memsz)
				continue;
			put32(p + off, 0x14);
			put32(p + off + 4, g_pa_mods[i].seg[s].perms);
			put32(p + off + 8, g_pa_mods[i].seg[s].vaddr);
			put32(p + off + 12, g_pa_mods[i].seg[s].memsz);
			put32(p + off + 16, 4);
			off += 0x14;
			nseg++;
		}
		put32(p + e + 0x4c, nseg);
		kmemset(p + off, 0, 16); off += 16;                  /* exidx / extab */
		put32(p + e, off - e);
		cnt++;
	}
	/* an application (not SceShell) gets the virtual Razor HUD */
	if (HUD_ENABLED && n > 0 && (int)pid != sceKernelGetProcessId() &&
	    off + 0x100 <= sizeof(g_dbg) - 16) {
		off = hud_module_entry(p, off);
		cnt++;
	}
	put32(p + cntoff, cnt);
	return off;
}

/* Thread records for GET_THREAD_INFO (0xAC) / _EX (0xD0). */
static unsigned int dbgp_threads(unsigned char *p, unsigned int off, unsigned int pid, int ex)
{
	int n = pa_linked() ? rrcPaGetThreads((int)pid, g_pa_threads, RRC_PA_MAX_THREADS) : 0;
	unsigned int size = ex ? 0xD0 : 0xAC, cnt = 0, cntoff;
	int i;

	put32(p + off, pid); off += 4;
	cntoff = off; off += 4;
	for (i = 0; i < n && off + size <= sizeof(g_dbg) - 16; i++) {
		unsigned char *e = p + off;

		kmemset(e, 0, size);
		put32(e + 0x00, size);
		put32(e + 0x04, g_pa_threads[i].tid);
		cpstr(e + 0x08, g_pa_threads[i].name, 32);
		put32(e + 0x2c, g_pa_threads[i].attr);
		put32(e + 0x30, g_pa_threads[i].status);
		put32(e + 0x34, g_pa_threads[i].entry);
		put32(e + 0x38, g_pa_threads[i].stack);
		put32(e + 0x3c, g_pa_threads[i].stack_size);
		put32(e + 0x4c, (unsigned int)g_pa_threads[i].priority);
		put32(e + 0x50, (unsigned int)g_pa_threads[i].priority);
		put32(e + 0x5c, (unsigned int)g_pa_threads[i].last_cpu);
		put32(e + 0x68, g_pa_threads[i].run_us_lo);
		put32(e + 0x6c, g_pa_threads[i].run_us_hi);
		put32(e + 0x70, 0x14);                               /* StopReason size */
		off += size;
		cnt++;
	}
	put32(p + cntoff, cnt);
	return off;
}

/* GET_THREAD_NAMES_RES: count | count * (u32 id, char name[32]); no pid echo. */
static unsigned int dbgp_thread_names(unsigned char *p, unsigned int off, unsigned int pid)
{
	int n = pa_linked() ? rrcPaGetThreads((int)pid, g_pa_threads, RRC_PA_MAX_THREADS) : 0;
	int i;

	put32(p + off, (unsigned int)(n < 0 ? 0 : n)); off += 4;
	for (i = 0; i < n; i++) {
		put32(p + off, g_pa_threads[i].tid);
		cpstr(p + off + 4, g_pa_threads[i].name, 32);
		off += 0x24;
	}
	return off;
}

/* Builds the reply to one DBGP request into g_dbg + 16; returns the payload length
 * (0 = no reply). Caller holds g_dbg_mtx. */
/* STOP_NOTIFICATION (DBGP 0x10/0xc0, DBGP_BREAKPOINT_STOP.md section 5): the process stopped,
 * one thread whose PC is the completion breakpoint. Razor matches the stop by that PC and the
 * pid; it does not look at the stop reason. */
static unsigned char g_hud_tx[16 + 0x300];

static int send_all(int s, const void *buf, unsigned int len);

static int hud_stop_notify(unsigned int pid)
{
	unsigned char *p = g_hud_tx + 16;
	unsigned int off = 12, e, tid;
	char name[40], path[48];
	RrcPaThread thr;
	SceUInt64 tick = sceKernelGetProcessTimeWide();

	if (g_hud_sock < 0)
		return -1;
	kmemset(g_hud_tx, 0, sizeof(g_hud_tx));
	kmemset(&thr, 0, sizeof(thr));
	if (!pa_linked() || rrcPaGetThreads((int)pid, &thr, 1) != 1)
		return -2;
	tid = thr.tid;
	p[0] = 0; p[1] = 0x10; p[2] = 0xc0; p[3] = 0;   /* seq 0, frag 0, key 0 */
	proc_name((SceUID)pid, sceKernelGetProcessId(), name, path);
	off += dbg_entry(p + off, pid, name, path, 0, 0,
	                 PROC_ATTR_LOADED | PROC_ATTR_DEBUGGABLE | PROC_ATTR_ATTACHED);
	put32(p + off, 0x20004);                        /* STOP_REASON_SOFTWARE_BRKPT */
	put32(p + off + 4, tid);
	put32(p + off + 8, 1);
	off += 12;
	e = off;                                        /* basic ThreadInfo, 0xAC */
	put32(p + e + 0x00, 0xAC);
	put32(p + e + 0x04, tid);
	cpstr(p + e + 0x08, thr.name, 32);
	put32(p + e + 0x2c, thr.attr);
	put32(p + e + 0x30, 1);
	put32(p + e + 0x34, thr.entry);
	put32(p + e + 0x38, thr.stack);
	put32(p + e + 0x3c, thr.stack_size);
	put32(p + e + 0x4c, (unsigned int)thr.priority);
	put32(p + e + 0x50, (unsigned int)thr.priority);
	put32(p + e + 0x70, 0x14);                      /* StopReason size */
	put32(p + e + 0x74, 0x20004);
	put32(p + e + 0x9c, HUD_BASE + HUD_BP_OFF);     /* CurrentPC = the completion breakpoint */
	off = e + 0xAC;
	put32(p + off, (unsigned int)tick);
	put32(p + off + 4, (unsigned int)(tick >> 32));
	off += 8;
	mkhdr(g_hud_tx, off, g_hud_flags, g_hud_node, PROTO_DBGP);
	LOGV("hud: stop notification, tid", tid);
	return send_all(g_hud_sock, g_hud_tx, 16 + off);
}

static int hud_write_host0(unsigned int total);    /* DRFP, below */

static int hud_finish(unsigned int pid, unsigned int total)
{
	int r;

	LOGV("hud: pmon ready, bytes", total);
	r = hud_write_host0(total);
	LOGV("hud: host0 write", (unsigned int)r);
	r = hud_stop_notify(pid);
	LOGV("hud: stop notify", (unsigned int)r);
	return r;
}

/* ----------------------------------------------------------- DRFP client
 *
 * host0: files over DECI protocol 0x11000 (DRFP_FORMAT.md): the target sends
 * [u32 code][u16 msgid][u16 0] + body, psp2tm answers code | 1 with the same msgid, first body
 * word = result (0 = OK). An absolute "C:/..." path (host0: stripped) opens that file on the PC.
 * The session thread hands matching answers over in g_drfp_res and signals g_drfp_sema.
 */
#define DRFP_OPEN         0x04
#define DRFP_CLOSE        0x06
#define DRFP_READ         0x08
#define DRFP_WRITE        0x0a
#define DRFP_WRITE_CHUNK  0x10000u
#define DRFP_READ_CHUNK   0x400u
#define DRFP_TIMEOUT_US   (10 * 1000 * 1000)

static SceUID g_drfp_sema = -1;
static unsigned char g_drfp_tx[16 + 8 + 0x20 + DRFP_WRITE_CHUNK + 4];
static unsigned char g_drfp_res[RXBUF];
static unsigned int g_drfp_res_len;
static volatile unsigned int g_drfp_wait;      /* msgid being waited for, 0 = none */
static unsigned short g_drfp_msgid;
static char g_hud_settings_path[0x200];
static char g_hud_pmon_path[0x200];
static char g_hud_settings[0x800];

/* Called by the session thread for every DRFP frame. */
static void drfp_answer(const unsigned char *pay, unsigned int paylen)
{
	if (paylen < 12 || !(get32(pay) & 1) || !g_drfp_wait || get16(pay + 4) != g_drfp_wait)
		return;
	g_drfp_res_len = paylen;
	kmemcpy(g_drfp_res, pay, paylen);
	g_drfp_wait = 0;
	sceKernelSignalSema(g_drfp_sema, 1);
}

/* Sends the command whose body (blen bytes) is already at g_drfp_tx + 24 and waits for the
 * answer. Returns the answer's result word (0 = OK) or a negative transport error. */
static int drfp_call(int sock, unsigned int code, unsigned int blen)
{
	SceUInt timeout = DRFP_TIMEOUT_US;
	unsigned int padded = (blen + 3u) & ~3u;

	if (g_drfp_sema < 0)
		return -1;
	while (sceKernelPollSema(g_drfp_sema, 1) >= 0)
		;
	while (blen < padded)
		g_drfp_tx[24 + blen++] = 0;
	if (++g_drfp_msgid == 0)
		g_drfp_msgid = 1;
	mkhdr(g_drfp_tx, 8 + padded, 0, DRFP_NODE, PROTO_DRFP);
	put32(g_drfp_tx + 16, code);
	put16(g_drfp_tx + 20, g_drfp_msgid);
	put16(g_drfp_tx + 22, 0);
	g_drfp_res_len = 0;
	g_drfp_wait = g_drfp_msgid;
	if (send_all(sock, g_drfp_tx, 16 + 8 + padded) < 0) {
		g_drfp_wait = 0;
		return -2;
	}
	if (sceKernelWaitSema(g_drfp_sema, 1, &timeout) < 0) {
		g_drfp_wait = 0;
		LOGV("drfp: no answer to command", code);
		return -3;
	}
	if (g_drfp_res_len < 12 || get32(g_drfp_res) != (code | 1))
		return -4;
	return (int)get32(g_drfp_res + 8);
}

/* "host0:C:/x/y" -> "C:/x/y" */
static const char *host0_strip(const char *path)
{
	if (path[0] == 'h' && path[1] == 'o' && path[2] == 's' && path[3] == 't' && path[4] == '0' &&
	    path[5] == ':')
		return path + 6;
	return path;
}

static int drfp_open(int sock, const char *host0_path, unsigned int flags, unsigned int mode,
                     unsigned int *fd)
{
	const char *path = host0_strip(host0_path);
	unsigned int n = kstrlen(path) + 1;
	int r;

	if (n > sizeof(g_drfp_tx) - 64)
		return -5;
	put32(g_drfp_tx + 24, flags);
	put32(g_drfp_tx + 28, mode);
	put32(g_drfp_tx + 32, n);
	kmemcpy(g_drfp_tx + 36, path, n);
	r = drfp_call(sock, DRFP_OPEN, 12 + n);
	if (r == 0) {
		if (g_drfp_res_len < 16)
			return -4;
		*fd = get32(g_drfp_res + 12);
	}
	return r;
}

static int drfp_close(int sock, unsigned int fd)
{
	put32(g_drfp_tx + 24, fd);
	return drfp_call(sock, DRFP_CLOSE, 4);
}

/* Whole small file into buf (NUL terminated); returns its length or < 0. */
static int drfp_read_file(int sock, const char *host0_path, char *buf, unsigned int cap)
{
	unsigned int fd, got = 0;
	int r = drfp_open(sock, host0_path, 0x001, 0x100, &fd);

	if (r != 0)
		return r < 0 ? r : -(0x10000 | (r & 0xffff));
	while (got + 1 < cap) {
		unsigned int want = cap - 1 - got, n;

		if (want > DRFP_READ_CHUNK)
			want = DRFP_READ_CHUNK;
		put32(g_drfp_tx + 24, fd);
		put32(g_drfp_tx + 28, 0);
		put32(g_drfp_tx + 32, got);           /* u64 offset */
		put32(g_drfp_tx + 36, 0);
		put32(g_drfp_tx + 40, want);
		r = drfp_call(sock, DRFP_READ, 20);
		if (r != 0 || g_drfp_res_len < 8 + 0x10)
			break;
		n = get32(g_drfp_res + 8 + 0x0c);
		if (n == 0 || n > want || g_drfp_res_len < 8 + 0x10 + n)
			break;
		kmemcpy(buf + got, g_drfp_res + 8 + 0x10, n);
		got += n;
	}
	buf[got] = 0;
	drfp_close(sock, fd);
	return (int)got;
}

/* Value of "key=" in the settings text, copied into out; 0 if missing. */
static int ini_value(const char *text, const char *key, char *out, unsigned int cap)
{
	unsigned int klen = kstrlen(key), i = 0;

	while (text[i]) {
		unsigned int j = 0, n = 0;

		while (j < klen && text[i + j] == key[j])
			j++;
		if (j == klen && text[i + j] == '=') {
			i += j + 1;
			while (text[i] && text[i] != '\r' && text[i] != '\n' && n + 1 < cap)
				out[n++] = text[i++];
			out[n] = 0;
			return 1;
		}
		while (text[i] && text[i] != '\n')
			i++;
		if (text[i])
			i++;
	}
	return 0;
}

/* From the arm command: the settings file Razor served (the command's string), its
 * trace_filename and trace_size. Falls back to tmp.pmon next to the settings file. */
static void hud_read_settings(int sock)
{
	char size[16];
	int n, i, slash = -1;

	g_hud_pmon_path[0] = 0;
	g_hud_trace_ms = HUD_TRACE_MS;
	size[0] = 0;
	kmemcpy(g_hud_settings_path, g_hud_arg, sizeof(g_hud_settings_path));
	if (!g_hud_settings_path[0])
		return;
	for (i = 0; g_hud_settings_path[i]; i++)
		if (g_hud_settings_path[i] == '/' || g_hud_settings_path[i] == '\\')
			slash = i;
	n = drfp_read_file(sock, g_hud_settings_path, g_hud_settings, sizeof(g_hud_settings));
	LOGV("hud: settings bytes", (unsigned int)n);
	if (n > 0) {
		LOG(g_hud_settings);
		ini_value(g_hud_settings, "trace_filename", g_hud_pmon_path, sizeof(g_hud_pmon_path));
		ini_value(g_hud_settings, "trace_size", size, sizeof(size));
	}
	if (!g_hud_pmon_path[0] && slash >= 0 && slash + 10 < (int)sizeof(g_hud_pmon_path)) {
		kmemcpy(g_hud_pmon_path, g_hud_settings_path, (unsigned int)slash + 1);
		kmemcpy(g_hud_pmon_path + slash + 1, "tmp.pmon", 9);
	}
	LOG(g_hud_pmon_path[0] ? g_hud_pmon_path : "hud: no trace file name");
	if (size[0])
		LOG(size);
	LOGV("hud: record ms", g_hud_trace_ms);
}

static int hud_write_host0(unsigned int total)
{
	unsigned int fd, off = 0;
	int r;

	if (!g_hud_pmon_path[0] || g_hud_sock < 0)
		return -10;
	if (!total)
		return -11;
	r = drfp_open(g_hud_sock, g_hud_pmon_path, 0x602, 0x180, &fd);   /* write, create, truncate */
	if (r != 0) {
		LOGV("hud: host0 open failed", (unsigned int)r);
		return r < 0 ? r : -12;
	}
	while (off < total) {
		unsigned int n = total - off;
		int got;

		if (n > DRFP_WRITE_CHUNK)
			n = DRFP_WRITE_CHUNK;
		got = gpu_trace_read(off, g_drfp_tx + 24 + 20, n);
		if (got != (int)n) {
			r = -13;
			break;
		}
		put32(g_drfp_tx + 24, fd);
		put32(g_drfp_tx + 28, 0);             /* flags: normal write, answer */
		put32(g_drfp_tx + 32, off);           /* u64 offset */
		put32(g_drfp_tx + 36, 0);
		put32(g_drfp_tx + 40, n);
		/* psp2tm's WRITE is a deferred overlapped write (FUN_1400c8e40): it issues each
		 * WriteFile async and completes the previous one on the next call, so byteswritten
		 * is cumulative and a real disk error surfaces on the following write or on CLOSE.
		 * Trust the result word, not a per-chunk byte count. */
		r = drfp_call(g_hud_sock, DRFP_WRITE, 20 + n);
		if (r != 0) {
			LOGV("hud: host0 write failed at", off);
			LOGV("  result", (unsigned int)r);
			break;
		}
		off += n;
	}
	{
		int cr = drfp_close(g_hud_sock, fd);   /* flushes the last overlapped write */

		if (r == 0 && cr != 0) {
			LOGV("hud: host0 close error", (unsigned int)cr);
			r = cr;
		}
	}
	LOGV("hud: host0 bytes sent", off);
	return r;
}

/* Sends the reply in g_dbg + 16. A payload above DBGP_FRAME_MAX goes out as fragments: the
 * first frame carries the header with the "more" bit, each continuation repeats the 12-byte
 * header with seq 1, 2, ... and appends raw bytes (DBGP_MODULE_THREAD_FORMAT.md section 1). */
#define DBGP_FRAME_MAX    0xC000u
static unsigned char g_dbg_frag[16 + DBGP_FRAME_MAX];

static int send_all(int s, const void *buf, unsigned int len);

static int dbgp_send(int sock, unsigned short flags, unsigned short node, unsigned int proto,
                     unsigned int plen)
{
	unsigned char *p = g_dbg + 16;
	unsigned int off = DBGP_FRAME_MAX, seq = 0;

	if (plen <= DBGP_FRAME_MAX) {
		mkhdr(g_dbg, plen, flags, node, proto);
		return send_all(sock, g_dbg, 16 + plen);
	}
	p[6] |= 1;
	mkhdr(g_dbg, DBGP_FRAME_MAX, flags, node, proto);
	if (send_all(sock, g_dbg, 16 + DBGP_FRAME_MAX) < 0)
		return -1;
	while (off < plen) {
		unsigned char *c = g_dbg_frag + 16;
		unsigned int n = plen - off;

		if (n > DBGP_FRAME_MAX - 12)
			n = DBGP_FRAME_MAX - 12;
		kmemcpy(c, p, 4);
		put16(c + 4, (unsigned short)++seq);
		c[6] = (unsigned char)(off + n < plen ? 1 : 0);
		c[7] = 0;
		put32(c + 8, 0);
		kmemcpy(c + 12, p + off, n);
		mkhdr(g_dbg_frag, 12 + n, flags, node, proto);
		if (send_all(sock, g_dbg_frag, 16 + 12 + n) < 0)
			return -1;
		off += n;
	}
	return 0;
}

static unsigned int dbgp_reply(const unsigned char *req, unsigned int len)
{
	unsigned char *p = g_dbg + 16;
	unsigned int group = req[1], code = req[2];
	unsigned int a1 = len >= 8 ? get32(req + 4) : 0;
	unsigned int a2 = len >= 12 ? get32(req + 8) : 0;
	unsigned int off;

	if (code & 1)
		return 0;                           /* not a request */
	if (group == 0x20 && code == 0x00)
		return dbgp_procinfo();

	off = dbgp_hdr(p, req, 0);
	switch ((group << 8) | code) {
	case 0x1010: {                          /* RDMEM: pid | address | size -> pid | len | data */
		static unsigned int reads, fails;
		unsigned int size = len >= 16 ? get32(req + 12) : 0;
		int got = -1;

		/* psp2tm asks for at most 0x10000 at a time (DBGP_MODULE_THREAD_FORMAT.md 9a) */
		if (size == 0 || size > RRC_PA_READMEM_MAX) {
			put32(p + 8, DBGP_UNSUPPORTED);
			return off;
		}
		if (hud_contains(a2, size)) {
			hud_init();
			kmemcpy(p + off + 8, g_hud + (a2 - HUD_BASE), size);
			got = (int)size;
		} else if (pa_linked()) {
			/* e.g. Razor filling the game's code sections before it uses its symbols */
			got = rrcPaReadMemory((int)a1, a2, p + off + 8, size);
		}
		if (got != (int)size) {
			if (!fails++) {
				LOGV("rdmem failed at", a2);
				LOGV("  size", size);
				LOGV("  result", (unsigned int)got);
			}
			put32(p + 8, DBGP_UNSUPPORTED);
			return off;
		}
		if ((++reads & 0xFF) == 1)
			LOGV("rdmem reads so far", reads);
		put32(p + off, a1);
		put32(p + off + 4, size);
		off += 8 + size;
		while (off & 3)
			p[off++] = 0;
		return off;
	}
	case 0x1012: {                          /* WRMEM: pid | address | len | data -> pid | written */
		unsigned int wlen = len >= 16 ? get32(req + 12) : 0;

		if (!hud_contains(a2, wlen) || len < 16 + wlen) {
			put32(p + 8, DBGP_UNSUPPORTED);
			return off;
		}
		hud_init();
		kmemcpy(g_hud + (a2 - HUD_BASE), req + 16, wlen);
		if (a2 == HUD_BASE + HUD_CMD_OFF)
			hud_command(a1, g_hud + HUD_CMD_OFF, wlen);
		put32(p + off, a1);
		put32(p + off + 4, wlen);
		return off + 8;
	}
	case 0x104a: {                          /* SET_SWBRKPT: only the virtual HUD's completion address */
		unsigned int addr = len >= 0x18 ? get32(req + 0x14) : 0;
		unsigned int thumb = len >= 0x1c ? (get32(req + 0x18) & 1) : 0;

		LOGV("set sw breakpoint", addr | thumb);
		if (!hud_contains(addr, 4)) {
			put32(p + 8, DBGP_UNSUPPORTED);
			return off;
		}
		g_hud_bp_id++;
		put32(p + off, a1);                 /* pid */
		put32(p + off + 4, g_hud_bp_id);    /* BreakPtId, given back on CLEAR */
		put32(p + off + 8, thumb ? 2 : 4);  /* original opcode size / opcode: a NOP (not read by Razor) */
		put32(p + off + 12, thumb ? 0xBF00u : 0xE320F000u);
		return off + 16;
	}
	case 0x104c:                            /* CLEAR_SWBRKPT: pid | id -> pid | id */
		LOGV("clear sw breakpoint", a2);
		put32(p + off, a1);
		put32(p + off + 4, a2);
		return off + 8;
	case 0x2010:                            /* ATTACH_PROCESS: header only */
		g_attached_pid = (int)a1;
		return off;
	case 0x2012:                            /* DETACH_PROCESS */
		if ((int)a1 == g_attached_pid)
			g_attached_pid = -1;
		return off;
	case 0x2020:                            /* SUSPEND_PROCESS: 0x20056 = success, no data */
		put32(p + 8, 0x20056);
		return off;
	case 0x2022:                            /* RESUME_PROCESS: pid | 0 threads */
		put32(p + off, a1); put32(p + off + 4, 0);
		return off + 8;
	case 0x2024:                            /* SUSPEND / RESUME_APPLICATION: pid */
	case 0x2026:
		put32(p + off, a1);
		return off + 4;
	case 0x4000:                            /* GET_MOD_INFO */
		return dbgp_modules(p, off, a1);
	case 0x4002:                            /* GET_META_DATA: pid | modid | 0 bytes */
		put32(p + off, a1); put32(p + off + 4, a2); put32(p + off + 8, 0);
		return off + 12;
	case 0x4010:                            /* GET_LIB_INFO: pid | 0 */
		put32(p + off, a1); put32(p + off + 4, 0);
		return off + 8;
	case 0x3000:                            /* GET_THREAD_INFO */
		return dbgp_threads(p, off, a1, 0);
	case 0x3002:                            /* GET_THREAD_INFO_EX */
		return dbgp_threads(p, off, a1, 1);
	case 0x3010:                            /* SUSPEND / RESUME_THREAD: pid | tid [| status] */
		put32(p + off, a1); put32(p + off + 4, a2); put32(p + off + 8, 2);
		return off + 12;
	case 0x3012:
		put32(p + off, a1); put32(p + off + 4, a2);
		return off + 8;
	case 0x3014:                            /* GET_THREAD_NAMES */
		return dbgp_thread_names(p, off, a1);
	case 0x3016:                            /* GET_STACK_INFO: 0 */
	case 0x3032:                            /* GET_FIBER_STACK_INFO: 0 */
		put32(p + off, 0);
		return off + 4;
	case 0x3020:                            /* GET_SYNC_INFO: pid, no objects */
		put32(p + off, a1);
		return off + 4;
	case 0x3030:                            /* GET_APP_OBJECT_INFO: 0 | 0 */
		put32(p + off, 0); put32(p + off + 4, 0);
		return off + 8;
	default:                                /* refuse immediately rather than time out */
		put32(p + 8, DBGP_UNSUPPORTED);
		return off;
	}
}

/* ------------------------------------------------------------ connections */

static unsigned char g_rx[MAX_CONN][RXBUF];
static unsigned char g_tx[MAX_CONN][TXBUF];
static unsigned char g_udp_rx[UDPBUF];
static unsigned char g_udp_tx[UDPBUF];
static int g_slot_busy[MAX_CONN];
static int g_slot_sock[MAX_CONN];
static volatile int g_slot_kill[MAX_CONN];     /* set by session_kill_locked: serve() returns */
static SceUInt64 g_slot_rx_at[MAX_CONN];       /* when the session last received a frame */
static int g_run = 1;

/* Slot state is changed by the accept loop, the session threads, the status thread and
 * net_reset(). A session's own thread closes its socket; the others only shut it down, and
 * this lock keeps them from doing that to a socket number already closed and reused. */
static SceUID g_slot_mtx = -1;

static void slot_lock(void)
{
	if (g_slot_mtx >= 0)
		sceKernelLockMutex(g_slot_mtx, 1, 0);
}

static void slot_unlock(void)
{
	if (g_slot_mtx >= 0)
		sceKernelUnlockMutex(g_slot_mtx, 1);
}

/* Ends a session from another thread: shutdown makes a blocked receive read end of stream
 * and fails a blocked send, abort does the same for anything else SceNet is waiting on.
 * The session thread then sees g_slot_kill, closes the socket and frees the slot.
 * Call with the slot lock held. */
static void session_kill_locked(int slot)
{
	int s = g_slot_sock[slot];

	if (!g_slot_busy[slot] || s < 0 || g_slot_kill[slot])
		return;
	g_slot_kill[slot] = 1;
	sceNetShutdown(s, SCE_NET_SHUT_RDWR);
	sceNetSocketAbort(s, 0);
}

/* A session socket has two writers: its serve() thread (replies, including
 * multi-frame trace reads) and the status thread (console pushes). Frames must
 * not interleave, so every send holds this lock. Session sockets have a send
 * timeout (SEND_TIMEOUT_US), so a PC that has gone away cannot hold it for the
 * minutes TCP spends retransmitting. */
static SceUID g_send_mtx = -1;

static int send_all(int s, const void *buf, unsigned int len)
{
	const unsigned char *p = (const unsigned char *)buf;
	unsigned int sent = 0;
	int rc = 0;

	if (g_send_mtx >= 0)
		sceKernelLockMutex(g_send_mtx, 1, 0);
	while (sent < len) {
		int r = sceNetSend(s, p + sent, len - sent, 0);
		if (r <= 0) {
			rc = -1;
			break;
		}
		sent += (unsigned int)r;
	}
	if (g_send_mtx >= 0)
		sceKernelUnlockMutex(g_send_mtx, 1);
	return rc;
}

/* A receive-timeout (SCE_NET_SO_RCVTIMEO) means the peer is simply idle, not gone;
 * distinguish it from a real close/error. sceNetRecv may surface it as the return
 * value or via errno, so check both. */
static int recv_timed_out(int r)
{
	int e;

	if (r == (int)SCE_NET_ERROR_ETIMEDOUT || r == (int)SCE_NET_ERROR_EAGAIN)
		return 1;
	e = sceNetErrnoLoc() ? *sceNetErrnoLoc() : 0;
	return e == (int)SCE_NET_ERROR_ETIMEDOUT || e == (int)SCE_NET_ERROR_EAGAIN ||
	       e == 0x76 /* ETIMEDOUT */ || e == 0x0b /* EAGAIN */ || e == 0x04 /* EINTR */;
}

/* Fully read len bytes. Return 0 on success, -1 on close/error or when the
 * session has been ended from outside (g_slot_kill). A timeout with bytes
 * already in hand keeps waiting (mid-frame); a timeout with nothing yet
 * returns -2 (idle at a frame boundary) so the caller can decide whether to wait. */
static int recv_all_idle(int s, int slot, void *buf, unsigned int len)
{
	unsigned char *p = (unsigned char *)buf;
	unsigned int got = 0;

	while (got < len) {
		int r;

		/* Checked on every pass: an aborted socket may keep failing with EINTR,
		 * which recv_timed_out() reads as idle. */
		if (g_slot_kill[slot])
			return -1;
		r = sceNetRecv(s, p + got, len - got, 0);
		if (r > 0) {
			got += (unsigned int)r;
			continue;
		}
		if (r == 0)                     /* orderly shutdown by the peer */
			return -1;
		if (recv_timed_out(r)) {
			if (got == 0)
				return -2;              /* nothing received yet: idle */
			continue;                   /* partway through a frame: keep waiting */
		}
		return -1;
	}
	return 0;
}

/* Timeout is fatal (used before a session is established, to reap dead probes). */
static int recv_all(int s, int slot, void *buf, unsigned int len)
{
	int r = recv_all_idle(s, slot, buf, len);

	return r == 0 ? 0 : -1;
}

static int ttyp_send(int sock, unsigned char *tx, const char *text);
static int status_thread(SceSize args, void *argp);
static unsigned int app(char *dst, unsigned int n, const char *s);
static volatile int g_con_sock;        /* tentative; defined below as -1 */
static int g_pmep_logs;
static int g_capture;                  /* rrc_tty.skprx linked and answering */
static int g_greeted;                  /* greeting/self-check sent once per boot */

/* ------------------------------------------------ PAMP (Razor CPU and GPU trace)
 *
 * ../docs/PAMP.md. Request: u32 cmd | u32 id | u32 len | body. Response: u32 cmd | u32 id |
 * u32 bodyLen | u32 result | body. Notifications use cmd 0x8000000N and id 0.
 * CPU (ARM) trace: rrc_pa.skprx samples between START and STOP and encodes the PA buffer
 * while READ_TRACE_DATA streams it back in chunks flagged "more".
 * GPU trace: the game records its GPU CSV while the capture flag exists, and STOP turns it
 * into the .pmon that READ_TRACE_DATA streams (gpu_capture_stop, pmon_trace.c).
 */
#define PAMP_CHUNK      0xF000
static unsigned char g_pamp_tx[16 + 16 + 4 + PAMP_CHUNK];
static unsigned char g_bookmark_cfg[20];
static unsigned int g_pa_pid, g_pa_sample_mode, g_pa_period;
static int g_want_cpu, g_want_gpu;     /* traces created since OPEN */
static unsigned int g_gpu_pid, g_gpu_total;
static unsigned char g_gpu_create[0x48];

static unsigned int debuggable_pid(void);

static int pamp_send(int sock, unsigned short flags, unsigned short node, unsigned int cmd,
                     unsigned int id, unsigned int result, unsigned int bodylen)
{
	mkhdr(g_pamp_tx, 16 + bodylen, flags, node, PROTO_PAMP);
	put32(g_pamp_tx + 16, cmd);
	put32(g_pamp_tx + 20, id);
	put32(g_pamp_tx + 24, bodylen);
	put32(g_pamp_tx + 28, result);
	return send_all(sock, g_pamp_tx, 32 + bodylen);
}

static int pamp_handle(int sock, unsigned short flags, unsigned short node,
                       const unsigned char *pay, unsigned int paylen)
{
	unsigned int cmd, id, bl = 0, result = 0;
	const unsigned char *body;
	unsigned char *out = g_pamp_tx + 32;
	int linked = pa_linked();

	if (paylen < 12)
		return 0;
	cmd = get32(pay);
	id = get32(pay + 4);
	body = pay + 12;
	paylen -= 12;
	logline("pamp cmd", cmd, 1);

	switch (cmd) {
	case 0x00:                              /* OPEN */
		capture_flag_clear();
		g_want_cpu = g_want_gpu = 0;
		gpu_reset();
		if (!linked)
			result = 1;                     /* rrc_pa.skprx missing: capture cannot work */
		else
			rrcPaReset();
		break;
	case 0x01:                              /* CLOSE */
		capture_flag_clear();
		g_want_cpu = g_want_gpu = 0;
		gpu_reset();
		if (linked)
			rrcPaReset();
		break;
	case 0x02:                              /* TraceBufferAvailableSize */
		put32(out, 0x4000000);
		bl = 4;
		break;
	case 0x04:                              /* CREATE_TRACE: u32 sub, then per sub */
		LOGV("  create trace sub", paylen >= 4 ? get32(body) : 0xFFFFFFFFu);
		if (paylen >= 20 && get32(body) == 0) {
			/* ARM: traceMode | sampleMode | u16 ts | u16 sample | pid */
			g_pa_sample_mode = get32(body + 8);
			g_pa_period = get16(body + 14);
			g_pa_pid = get32(body + 16);
			g_want_cpu = 1;
		} else if (paylen >= 4 && get32(body) == 2) {
			/* GPU: control, u16 sample rate, u16 counted rate, 4 x u32[4] masks */
			unsigned int n = paylen - 4 < sizeof(g_gpu_create) ? paylen - 4 : sizeof(g_gpu_create);

			kmemset(g_gpu_create, 0, sizeof(g_gpu_create));
			kmemcpy(g_gpu_create, body + 4, n);
			LOGV("  gpu control", get32(g_gpu_create));
			LOGV("  gpu rates", get32(g_gpu_create + 4));
			g_want_gpu = 1;
		}
		break;
	case 0x05:                              /* DESTROY_TRACE: trace type */
		LOGV("  destroy trace", paylen >= 4 ? get32(body) : 0xFFFFFFFFu);
		if (paylen >= 4 && get32(body) == 0)
			g_want_cpu = 0;
		else if (paylen >= 4 && get32(body) == 2)
			g_want_gpu = 0;
		break;
	case 0x06: {                            /* START_CAPTURE */
		unsigned int period = g_pa_period ? g_pa_period : 1000;   /* sample period, taken as us */
		/* Games run on cores 0-2; SceShell (the fallback target) runs on core 3. */
		unsigned int cpus = (int)g_pa_pid == sceKernelGetProcessId() ? 0xF : 0x7;
		int r = 0;

		if (!g_want_cpu && !g_want_gpu)
			g_want_cpu = 1;                 /* a START with no CREATE: behave as before */
		if (g_want_gpu) {
			g_gpu_pid = g_want_cpu ? g_pa_pid : debuggable_pid();
			g_gpu_total = 0;
			gpu_capture_start();
			LOGV("gpu trace start, pid", g_gpu_pid);
		}
		if (!g_want_cpu) {
			capture_flag_set(g_gpu_pid);
			if (pamp_send(sock, flags, node, cmd, id, 0, 0) < 0)
				return -1;
			put32(out, 0);                  /* START_NOTIFICATION, reason CAPTURE */
			return pamp_send(sock, flags, node, 0x80000000u, 0, 0, 4);
		}
		r = linked ? rrcPaStart((int)g_pa_pid, period, cpus, RRC_PA_PC_REGISTERS) : -1;

		logline("pa start result", (unsigned int)r, 1);
		LOGV("  pid", g_pa_pid);
		LOGV("  sample mode", g_pa_sample_mode);
		LOGV("  sample period", g_pa_period);
		if (linked) {
			int n = rrcPaGetThreads((int)g_pa_pid, g_pa_threads, 6), t;

			LOGV("  threads (first 6 logged)", (unsigned int)n);
			for (t = 0; t < n && t < 6; t++) {
				LOGV("    tid", g_pa_threads[t].tid);
				LOGV("    status", g_pa_threads[t].status);
				LOGV("    last cpu", (unsigned int)g_pa_threads[t].last_cpu);
				LOGV("    run us", g_pa_threads[t].run_us_lo);
			}
		}
		if (r < 0) {
			result = 1;
			break;
		}
		capture_flag_set(g_pa_pid);
		if (pamp_send(sock, flags, node, cmd, id, 0, 0) < 0)
			return -1;
		put32(out, 0);                      /* START_NOTIFICATION, reason CAPTURE */
		return pamp_send(sock, flags, node, 0x80000000u, 0, 0, 4);
	}
	case 0x07: {                            /* STOP_CAPTURE */
		int r;
		RrcPaInfo info;
		SceUInt64 t0;

		capture_flag_clear();
		if (g_want_gpu && !g_gpu_ready)
			g_gpu_total = gpu_capture_stop(g_gpu_pid);
		if (!g_want_cpu)
			goto stopped;
		t0 = sceKernelGetProcessTimeWide();
		r = linked ? rrcPaStop() : 0;

		logline("pa stop bytes", (unsigned int)r, 1);
		LOGV("  stop ms (sort + size pass)", (unsigned int)(sceKernelGetProcessTimeWide() - t0) / 1000u);
		if (linked && rrcPaGetInfo(&info) >= 0) {
			LOGV("  records", info.records);
			LOGV("  pc samples", info.pc_samples);
			LOGV("  register errors", info.reg_errors);
			LOGV("  last register error", info.last_reg_error);
			LOGV("  intervals", info.intervals);
			LOGV("  ticks", info.ticks);
			LOGV("  slowest tick us", info.max_tick_us);
			LOGV("  mean tick us", info.avg_tick_us);
			LOGV("  threads listed", info.threads_listed);
			LOGV("  threads eligible (all cpus)", info.threads_eligible);
			LOGV("  dropped", info.records_dropped);
			LOGV("  resume errors", info.resume_errors);
			LOGV("  last error", info.last_error);
		}
	stopped:
		if (pamp_send(sock, flags, node, cmd, id, 0, 0) < 0)
			return -1;
		put32(out, 0);                      /* STOP_NOTIFICATION, reason CAPTURE */
		return pamp_send(sock, flags, node, 0x80000001u, 0, 0, 4);
	}
	case 0x08: {                            /* GET_TRACE_INFO: status | buffer1 bytes | buffer2 bytes */
		RrcPaInfo info;

		unsigned int cpu_bytes;

		kmemset(&info, 0, sizeof(info));
		if (linked)
			rrcPaGetInfo(&info);
		cpu_bytes = g_want_cpu ? info.encoded_bytes : 0;
		put32(out, info.state == RRC_PA_STATE_CAPTURING ? 1 : 0);
		/* the GPU trace goes in buffer 1 on its own, buffer 2 next to a CPU trace */
		put32(out + 4, g_want_cpu ? cpu_bytes : g_gpu_total);
		put32(out + 8, g_want_cpu && g_want_gpu ? g_gpu_total : 0);
		LOGV("  trace info cpu", cpu_bytes);
		LOGV("  trace info gpu", g_want_gpu ? g_gpu_total : 0);
		bl = 12;
		break;
	}
	case 0x09: {                            /* READ_TRACE_DATA: buffer | offset | count */
		unsigned int buffer = paylen >= 12 ? get32(body) : 0;
		unsigned int off = paylen >= 12 ? get32(body + 4) : 0;
		unsigned int count = paylen >= 12 ? get32(body + 8) : 0;
		unsigned int total = 0;
		int gpu = g_want_gpu && (!g_want_cpu || buffer != 0);
		RrcPaInfo info;

		/* Both traces are encoded while they are read (no whole-trace buffer), so a read
		 * takes a little time; the sizes are known from the stop. */
		if (gpu)
			total = g_gpu_total;
		else if (linked && rrcPaGetInfo(&info) >= 0)
			total = info.encoded_bytes;
		if (off >= total)
			count = 0;
		else if (count > total - off)
			count = total - off;
		logline(gpu ? "gpu read offset" : "pa read offset", off, 1);
		LOGV("  buffer", buffer);
		LOGV("  bytes", count);
		do {
			unsigned int want = count > PAMP_CHUNK ? PAMP_CHUNK : count;
			int got = !want ? 0 : gpu ? gpu_trace_read(off, out + 4, want)
			                          : rrcPaRead(off, out + 4, want);

			if (got <= 0) {
				if (want)
					LOGV("  read failed at", off);
				got = 0;
				count = 0;
			}
			off += (unsigned int)got;
			count -= (unsigned int)got;
			put32(out, count ? 1 : 0);      /* more */
			if (pamp_send(sock, flags, node, cmd, id, 0, 4 + (unsigned int)got) < 0)
				return -1;
		} while (count);
		return 0;
	}
	case 0x0c:                              /* SET_BOOKMARK_CONFIG */
		if (paylen >= 20)
			kmemcpy(g_bookmark_cfg, body, 20);
		break;
	case 0x0d:                              /* GET_BOOKMARK_CONFIG */
		kmemcpy(out, g_bookmark_cfg, 20);
		bl = 20;
		break;
	case 0x0f:                              /* GET_BOOKMARK_INTERRUPT_COUNTS */
		kmemset(out, 0, 0x88);
		bl = 0x88;
		break;
	case 0x10:                              /* GET_GPU_SAMPLED_DATA */
		kmemset(out, 0, 16);
		bl = 16;
		break;
	case 0x12:                              /* TIMEBASE_FREQUENCY: Razor requires 333 (MHz) */
		put32(out, 333);
		bl = 4;
		break;
	default:                                /* config, triggers, bookmarks: accepted */
		break;
	}
	return pamp_send(sock, flags, node, cmd, id, result, bl);
}

/* ------------------------------------------------------------ VCP screenshot
 *
 * ../docs/VCP_FORMAT.md. Razor takes a screenshot at capture start and stop and aborts
 * the capture if it fails. FREEZE (0x10) -> FREEZE_RES (0x11) with the size;
 * GET_COMP_PICT (0x16) -> 0x17 frames whose chunks concatenate to a zlib stream
 * of width*height*4 RGBA bytes. The stream uses stored (uncompressed) deflate
 * blocks, one per frame, so no compressor is needed. The image is black for now.
 */
#define VCP_W           960
#define VCP_H           544
#define VCP_BLOCK       0xE000

static int vcp_handle(int sock, unsigned short flags, unsigned short node,
                      const unsigned char *pay, unsigned int paylen)
{
	unsigned char *o = g_pamp_tx + 16;
	unsigned int code;

	if (paylen < 4)
		return 0;
	code = get32(pay);
	if (code == 0x10) {                     /* FREEZE */
		put32(o, 0x11);
		put32(o + 4, 0);
		put32(o + 8, g_attached_pid > 0 ? (unsigned int)g_attached_pid : 0);
		put32(o + 12, 0);
		put32(o + 16, VCP_W);
		put32(o + 20, VCP_H);
		put32(o + 24, 0);                   /* A8B8G8R8 */
		mkhdr(g_pamp_tx, 28, flags, node, PROTO_VCP);
		return send_all(sock, g_pamp_tx, 16 + 28);
	}
	if (code == 0x16) {                     /* GET_COMP_PICT */
		unsigned int total = VCP_W * VCP_H * 4, done = 0;
		unsigned int s1 = 1, s2 = 0;

		while (done < total || done == 0) {
			unsigned int n = total - done > VCP_BLOCK ? VCP_BLOCK : total - done;
			unsigned int last = (done + n == total);
			unsigned int k = 16, i;

			put32(o, 0x17);
			put32(o + 4, 0);
			put32(o + 8, 0);
			put32(o + 12, last);
			if (done == 0) {
				o[k++] = 0x78;              /* zlib header, no dictionary */
				o[k++] = 0x01;
			}
			o[k++] = (unsigned char)last;   /* BFINAL, BTYPE = 00 stored */
			put16(o + k, n); k += 2;
			put16(o + k, ~n & 0xFFFF); k += 2;
			for (i = 0; i < n; i++) {
				unsigned char b = ((done + i) & 3) == 3 ? 0xFF : 0x00;   /* opaque black */

				o[k++] = b;
				s1 = (s1 + b) % 65521;
				s2 = (s2 + s1) % 65521;
			}
			done += n;
			if (last) {                     /* Adler-32, big-endian */
				unsigned int ad = (s2 << 16) | s1;

				o[k++] = (unsigned char)(ad >> 24);
				o[k++] = (unsigned char)(ad >> 16);
				o[k++] = (unsigned char)(ad >> 8);
				o[k++] = (unsigned char)ad;
			}
			mkhdr(g_pamp_tx, k, flags, node, PROTO_VCP);
			if (send_all(sock, g_pamp_tx, 16 + k) < 0)
				return -1;
			if (last)
				break;
		}
		return 0;
	}
	put32(o, code | 1);                     /* anything else: refuse */
	put32(o + 4, 0x1b);
	mkhdr(g_pamp_tx, 8, flags, node, PROTO_VCP);
	return send_all(sock, g_pamp_tx, 16 + 8);
}

/* ---------------------------------------------------------------- PMEP */
/* Battery Monitor. Wire format and RE evidence: ../docs/PMEP_FORMAT.md (verified
 * against psp2tm + PSP2BatteryMonitor.exe with tools/mock_pmep.py). */

/* Battery current is not reported. scePowerGetBatteryElec has a NID but no
 * declaration in VitaSDK, and calling it with no arguments hung this retail Vita
 * (rrc.log stopped right before it), so AI and the mA graph channel read 0. */

/* Virtual AC state set by SET_AC_STATUS (0x08); a retail Vita cannot switch
 * its supply, so this only drives what GET_AC_STATUS reports. */
static int g_pmep_vac;
static int g_pmep_raw_logged;

/* GET_PROPERTIES channels, in the order GET_STATUS reports their values.
 * units are eUnits: 1 MilliAmps (Power graph), 2 Celcius (Temperature tab). */
#define PMEP_NCH 2
static const char *const g_pmep_ch_name[PMEP_NCH] = { "Battery", "Temperature" };
static const unsigned int g_pmep_ch_units[PMEP_NCH] = { 1, 2 };

/* One PROPERTY record: u32 record_len (incl. itself) | u32 name_len |
 * UTF-8 name, NUL, pad4 | u32 units | u32 scale (float bits, 1.0f). */
static unsigned int pmep_prop(unsigned char *out, const char *name, unsigned int units)
{
	unsigned int nlen = kstrlen(name) + 1;
	unsigned int npad = align4(nlen);

	put32(out, 16 + npad);
	put32(out + 4, nlen);
	kmemcpy(out + 8, name, nlen);
	kmemset(out + 8 + nlen, 0, npad - nlen);
	put32(out + 8 + npad, units);
	put32(out + 12 + npad, 0x3F800000u);
	return 16 + npad;
}

/* scePowerGetBatteryTemp is degC x 100; the wire wants 0.1 K. */
static unsigned int pmep_decikelvin(void)
{
	int t = scePowerGetBatteryTemp();

	return (unsigned int)(t / 10 + 2732);
}

/* eBatteryValue id -> value, in the units psp2ctrl battery prints. */
static unsigned int pmep_battery_value(unsigned int id)
{
	int v;

	switch (id) {
	case 0:                                     /* BATTERY_TEMP, 0.1 K */
	case 6:                                     /* BATTERY_INTTEMP: no separate sensor */
		return pmep_decikelvin();
	case 1: v = scePowerGetBatteryVolt(); break;            /* mV */
	case 2: v = scePowerGetBatteryRemainCapacity(); break;  /* mAh */
	case 3: v = scePowerGetBatteryFullCapacity(); break;    /* mAh */
	case 4: return 0;                                       /* AI, mA: see above */
	case 5: v = scePowerGetBatteryLifeTime(); break;        /* minutes */
	case 7: v = scePowerGetBatterySOH(); break;             /* % */
	case 8: v = scePowerGetBatteryLifePercent(); break;     /* % */
	default: return 0;
	}
	return (unsigned int)(v < 0 ? 0 : v);
}

static void serve(int sock, int slot)
{
	unsigned char *rx = g_rx[slot];
	unsigned char *tx = g_tx[slot];

	if (recv_all(sock, slot, rx, 4) < 0) {
		LOG("greeting read failed");
		return;
	}
	if (rx[0] != 'D' || rx[1] != 'E' || rx[2] != 'C' || rx[3] != 'I') {
		LOG("not DECI");
		return;
	}
	LOG("got DECI");

	kmemset(tx, 0, 64);
	tx[0] = (unsigned char)((HANDSHAKE_MAGIC >> 24) & 0xff);
	tx[1] = (unsigned char)((HANDSHAKE_MAGIC >> 16) & 0xff);
	tx[2] = (unsigned char)((HANDSHAKE_MAGIC >> 8) & 0xff);
	tx[3] = (unsigned char)(HANDSHAKE_MAGIC & 0xff);
	tx[7] = 0x40;
	if (send_all(sock, tx, 64) < 0) {
		LOG("handshake send failed");
		return;
	}
	LOG("handshake ok");

	while (g_run) {
		unsigned int len, proto, paylen;
		unsigned short flags, node;
		unsigned char *pay;
		int r;

		/* An established session goes quiet between requests -- during a Razor
		 * capture, for a minute or more. A receive-timeout here is that idle,
		 * not a disconnect, so wait again instead of dropping the session (which
		 * showed up as Razor's "Target not connected. Cannot suspend process"
		 * when a capture ran past the socket's receive timeout). */
		r = recv_all_idle(sock, slot, rx, 16);
		if (r == -2)
			continue;
		if (r < 0)
			return;
		g_slot_rx_at[slot] = sceKernelGetProcessTimeWide();
		len = (unsigned int)rx[0] | ((unsigned int)rx[1] << 8) |
		      ((unsigned int)rx[2] << 16);
		if (rx[3] != MARKER || len < 16 || len > MAXPAY)
			return;
		paylen = len - 16;
		if (paylen > RXBUF - 16)
			return;
		if (paylen) {
			/* The header arrived; the body belongs to it. Wait through idle
			 * (-2) until it is all here, and fail only on a real close. */
			while ((r = recv_all_idle(sock, slot, rx + 16, paylen)) == -2)
				;
			if (r < 0)
				return;
		}

		flags = get16(rx + 4);
		node  = get16(rx + 6);
		proto = get32(rx + 8);
		pay   = rx + 16;

		if (proto == PROTO_NETMP) {
			unsigned char code = paylen ? pay[0] : 0xff;
			unsigned char rc = 0;
			unsigned int bl = netmp_body(code, tx + 20, &rc);

			if (bl == 0)
				continue;
			mkhdr(tx, 4 + bl, flags, node, proto);
			tx[16] = rc; tx[17] = 0; put16(tx + 18, 0);
			if (send_all(sock, tx, 16 + 4 + bl) < 0)
				return;
			if (rc == 11) {
				/* Session established: publish the socket so the console
				 * thread can push on it. Neighborhood + Console Output open
				 * and reopen many sessions, so the greeting and the
				 * capture self-check are sent ONCE per boot, not per
				 * session -- otherwise Console Output fills with duplicates. */
				g_con_sock = sock;
				LOG("session up, console channel live");
				if (!g_greeted) {
					char hello[96];
					unsigned int hn = 0;

					g_greeted = 1;
					hn = app(hello, hn, "[rrc] connected, firmware ");
					hn = app(hello, hn, fw_string());
					hn = app(hello, hn, "\n");
					hello[hn] = 0;
					ttyp_send(sock, tx, hello);
					if (g_capture)
						/* SceShell printf -> kernel putchar sink (rrc_tty)
						 * -> ring -> console thread -> this session: one
						 * captured line proving the pipe end to end. */
						sceClibPrintf("[rrc] capture live: device printf "
							"reaches Console Output\n");
					else
						ttyp_send(sock, tx,
							"[rrc] rrc_tty.skprx is not loaded: device printf "
							"output is not captured. See plugin/README.md.\n");
				}
			}
			continue;
		}
		if (proto == PROTO_PMEP) {
			/* Power monitor (Battery Monitor). Payload: u8 code, 3 zero bytes,
			 * u32 arg, u32 seq, then the body. The reply is code + 1 with arg
			 * and seq echoed; psp2tm waits only 0.5 s for it. Formats in
			 * ../docs/PMEP_FORMAT.md. */
			const unsigned char *cb = pay + 12;
			unsigned char code, *b;
			unsigned int arg, seq, cblen, bl, n, i;

			if (paylen < 12)
				continue;
			code = pay[0];
			arg = get32(pay + 4);
			seq = get32(pay + 8);
			cblen = paylen - 12;
			if (g_pmep_logs < 24) {
				g_pmep_logs++;
				logline("pmep cmd code/paylen", ((unsigned int)code << 16) | paylen, 1);
			}
			b = tx + 28;
			switch (code) {
			case 0x00:         /* GET_PROPERTIES: result | 0 | count | records */
				put32(b + 0, 0);
				put32(b + 4, 0);
				put32(b + 8, PMEP_NCH);
				bl = 12;
				for (i = 0; i < PMEP_NCH; i++)
					bl += pmep_prop(b + bl, g_pmep_ch_name[i], g_pmep_ch_units[i]);
				break;
			case 0x02: {       /* GET_STATUS: result | count | u16 value per channel */
				int tc = scePowerGetBatteryTemp() / 100;

				put32(b + 0, 0);
				put32(b + 4, PMEP_NCH);
				put16(b + 8, 0);  /* Battery mA: no safe retail source */
				put16(b + 10, (unsigned short)(tc < 0 ? 0 : tc));
				bl = 12;
				break;
			}
			case 0x04:         /* GET_BATTERY_VALUES: count | ids -> result | count | {id, value} */
				/* Log each scePower reading once, one call per line, so the units
				 * can be checked and a call that hangs shows as the missing line.
				 * Temp was confirmed as degC x 100 (0x0BEB = 30.51 C). */
				if (!g_pmep_raw_logged) {
					g_pmep_raw_logged = 1;
					LOGV("pmep raw temp", scePowerGetBatteryTemp());
					LOGV("pmep raw volt", scePowerGetBatteryVolt());
					LOGV("pmep raw remain", scePowerGetBatteryRemainCapacity());
					LOGV("pmep raw full", scePowerGetBatteryFullCapacity());
					LOGV("pmep raw lifetime", scePowerGetBatteryLifeTime());
					LOGV("pmep raw soh", scePowerGetBatterySOH());
					LOGV("pmep raw percent", scePowerGetBatteryLifePercent());
					LOGV("pmep raw online", scePowerIsPowerOnline());
				}
				n = 0;
				if (cblen >= 4) {
					n = get32(cb);
					if (n > (cblen - 4) / 4)
						n = (cblen - 4) / 4;
				}
				if (n > 16)
					n = 16;
				put32(b + 0, 0);
				put32(b + 4, n);
				for (i = 0; i < n; i++) {
					unsigned int id = get32(cb + 4 + 4 * i);

					put32(b + 8 + 8 * i, id);
					put32(b + 12 + 8 * i, pmep_battery_value(id));
				}
				bl = 8 + 8 * n;
				break;
			case 0x06:         /* SET_BATTERY_VALUES: DevKit battery emulation, not on retail */
				put32(b + 0, 1);
				bl = 4;
				break;
			case 0x08:         /* SET_AC_STATUS (Virtual AC): u32 plugged -> result */
				g_pmep_vac = cblen >= 4 && get32(cb) != 0;
				put32(b + 0, 0);
				bl = 4;
				break;
			case 0x0C:         /* GET_AC_STATUS: result | plugged */
				put32(b + 0, 0);
				put32(b + 4, (g_pmep_vac || scePowerIsPowerOnline()) ? 1 : 0);
				bl = 8;
				break;
			case 0x12:         /* GET_POWER_STATUS (voltages): result | count 0 */
				put32(b + 0, 0);
				put32(b + 4, 0);
				bl = 8;
				break;
			default:           /* responses and unknown commands: no reply */
				continue;
			}
			mkhdr(tx, 12 + bl, flags, node, proto);
			tx[16] = (unsigned char)(code + 1);
			tx[17] = 0; put16(tx + 18, 0);
			put32(tx + 20, arg); put32(tx + 24, seq);
			if (send_all(sock, tx, 16 + 12 + bl) < 0)
				return;
			continue;
		}
		if (proto == PROTO_DRFP) {
			drfp_answer(pay, paylen);
			continue;
		}
		if (proto == PROTO_DBGP) {
			/* Replies can be large, so they use their own buffer, not the
			 * per-slot tx; the buffer is shared, hence the lock. */
			if (paylen >= 4) {
				unsigned int plen;
				int bad;

				if (g_dbg_mtx >= 0)
					sceKernelLockMutex(g_dbg_mtx, 1, 0);
				g_dbgp_sock = sock;
				g_dbgp_flags = flags;
				g_dbgp_node = node;
				plen = dbgp_reply(pay, paylen);
				bad = 0;
				if (plen)
					bad = dbgp_send(sock, flags, node, proto, plen) < 0;
				if (g_dbg_mtx >= 0)
					sceKernelUnlockMutex(g_dbg_mtx, 1);
				if (bad)
					return;
			}
			continue;
		}
		if (proto == PROTO_PAMP || proto == PROTO_VCP) {
			int r;

			/* Both reply from g_pamp_tx; g_dbg_mtx serialises it across sessions. */
			if (g_dbg_mtx >= 0)
				sceKernelLockMutex(g_dbg_mtx, 1, 0);
			if (proto == PROTO_PAMP)
				r = pamp_handle(sock, flags, node, pay, paylen);
			else
				r = vcp_handle(sock, flags, node, pay, paylen);
			if (g_dbg_mtx >= 0)
				sceKernelUnlockMutex(g_dbg_mtx, 1);
			if (r < 0)
				return;
			continue;
		}
		if (proto == PROTO_CPUP) {
			unsigned char code;
			unsigned int arg, seq, bl;

			if (paylen < 12)
				continue;
			code = pay[0];
			arg = get32(pay + 4);
			seq = get32(pay + 8);
			if (code & 1)
				continue;
			bl = (code + 1 == 1) ? 0x18 : ((code + 1 == 3) ? 8 :
			     ((code + 1 == 0x0b) ? 0x10 : 4));
			kmemset(tx + 28, 0, bl);
			mkhdr(tx, 12 + bl, flags, node, proto);
			tx[16] = (unsigned char)(code + 1);
			tx[17] = 0; put16(tx + 18, 0);
			put32(tx + 20, arg); put32(tx + 24, seq);
			if (send_all(sock, tx, 16 + 12 + bl) < 0)
				return;
			continue;
		}
		if (proto != PROTO_TSMP || paylen < 12)
			continue;
		{
			unsigned char t = pay[0], c = pay[1];
			unsigned int arg = get32(pay + 4);
			unsigned int seq = get32(pay + 8);
			unsigned int rlen;

			if ((c & 1) || t == 6)
				continue;
			rlen = tsmp_body(t, c, pay + 12, paylen - 12, tx + 28);
			if (28 + rlen > TXBUF)
				continue;
			mkhdr(tx, 12 + rlen, flags, node, proto);
			tx[16] = t; tx[17] = (unsigned char)(c + 1);
			put16(tx + 18, 0);
			put32(tx + 20, arg); put32(tx + 24, seq);
			if (send_all(sock, tx, 16 + 12 + rlen) < 0)
				return;

			/* POWER_CONTROL_CMD (type 4 code 2): Neighborhood's Reboot /
			 * Power Off / Suspend. The RES above is result=0; now actually
			 * perform it, or the host errors ("forcibly turned off during
			 * shutdown" / INTERRUPT). Body word = ePowerOperation, confirmed on
			 * the wire: 0 = BOOT (Reboot), 0x80 = SHUTDOWN (Power Off),
			 * 0x81 = SUSPEND. Only those three act, so a stray POWER_CONTROL
			 * can never power-cycle the console. The connection dies with the
			 * device, so blocking here is fine. */
			if (t == 4 && c == 2) {
				unsigned int op = paylen >= 16 ? get32(pay + 12) : 0xffffffff;

				logline("power ctrl op/arg", (op << 16) | (arg & 0xffff), 1);
				/* Do NOT power down yet. The host now polls POWER_STATUS and
				 * waits (up to ~10s) for it to read OFF (reboot/power off) or
				 * SUSPENDED (suspend) before it considers the operation clean;
				 * POWER_STATUS reports that transition while g_power_op is set.
				 * The status thread performs the real scePower* call a few
				 * seconds later, after the host has seen the transition. */
				if (op == 0 || op == 0x80 || op == 0x81) {
					g_power_op = op;
					g_power_at = sceKernelGetProcessTimeWide() + 3 * 1000 * 1000;
				}
				continue;
			}
		}
	}
}

/* ------------------------------------------------------ TTYP console push
 *
 * The target pushes console text unsolicited; nothing is requested of us and
 * no response comes back. Layout from psp2tm's handler FUN_140134850:
 *   16-byte frame header, proto = 0x800300NN, node 0xa000, then
 *   +0x00 u16 source   0x1000 USER / 0x8000 KERNEL
 *   +0x02 u8  flags    MUST be 0 (bit0 = discard, bit1 = no text delivered)
 *   +0x03 u8  reserved
 *   +0x04 u32 processId
 *   +0x08 u32 threadId
 *   +0x0c u32 sequence
 *   +0x10 u64 tickTimestamp
 *   +0x18 u32 textLength   must equal total_length - 44
 *   +0x1c     text
 */
static unsigned int g_ttyp_seq;

/* Build and send one TTYP frame. stream selects the Console Output channel
 * (RRC_TTY_STREAM_*); psp2tm keys its per-line reassembly on
 * (stream, processId, threadId), so a line split across frames is joined. */
static int ttyp_frame(int sock, unsigned char *tx, unsigned char stream,
                      unsigned short source, unsigned int pid, unsigned int tid,
                      SceUInt64 tick, const char *text, unsigned int tlen)
{
	if (tlen > TXBUF - 16 - 28)
		tlen = TXBUF - 16 - 28;

	mkhdr(tx, 28 + tlen, 0, (unsigned short)(0xa000 | stream), PROTO_TTYP | stream);
	put16(tx + 16 + 0x00, source);
	tx[16 + 0x02] = 0;                        /* flags must be 0 */
	tx[16 + 0x03] = 0;
	put32(tx + 16 + 0x04, pid);
	put32(tx + 16 + 0x08, tid);
	put32(tx + 16 + 0x0c, g_ttyp_seq++);
	put32(tx + 16 + 0x10, (unsigned int)(tick & 0xffffffffu));
	put32(tx + 16 + 0x14, (unsigned int)(tick >> 32));
	put32(tx + 16 + 0x18, tlen);
	kmemcpy(tx + 16 + 0x1c, text, tlen);
	return send_all(sock, tx, 16 + 28 + tlen);
}

/* A whole line from the plugin itself (hello, warnings, the tailed file):
 * user stream, no process, current tick. */
static int ttyp_send(int sock, unsigned char *tx, const char *text)
{
	return ttyp_frame(sock, tx, RRC_TTY_STREAM_STDOUT, RRC_TTY_SOURCE_USER,
	                  0, 0, sceKernelGetProcessTimeWide(), text, kstrlen(text));
}

/* One captured record from rrc_tty.skprx, preserving its stream/pid/tid/tick. */
static int ttyp_send_rec(int sock, unsigned char *tx, const RrcTtyRecord *r)
{
	SceUInt64 tick = ((SceUInt64)r->tick_hi << 32) | r->tick_lo;
	unsigned int len = r->len > RRC_TTY_TEXT ? RRC_TTY_TEXT : r->len;

	return ttyp_frame(sock, tx, r->stream, r->source, r->pid, r->tid,
	                  tick, r->text, len);
}

/* --------------------------------------------- device console capture link
 *
 * rrc_tty.skprx (kernel) registers on the two SceSysmem debug sinks a DevKit's
 * TTY uses and buffers the device's real output. Its import library is linked
 * weakly, so the plugin still loads when rrc_tty.skprx is absent. Until the
 * loader resolves a weak import, the stub still holds the toolchain's
 * placeholder words; a resolved stub starts with an ARM instruction
 * (condition AL, top nibble 0xE). Check that, then require the version. */
#define TTY_BATCH 32
static RrcTtyRecord g_tty_rec[TTY_BATCH];

static int capture_linked(RrcTtyInfo *info)
{
	const unsigned int *stub = (const unsigned int *)((unsigned int)&rrcTtyGetInfo & ~1u);

	if ((stub[0] & 0xf0000000u) != 0xe0000000u)
		return 0;
	kmemset(info, 0, sizeof(*info));
	if (rrcTtyGetInfo(info) < 0)
		return 0;
	return info->version == RRC_TTY_VERSION;
}

static void log_capture(const RrcTtyInfo *info)
{
	LOG("rrc_tty capture linked");
	LOGV("  handlers", info->handlers);
	LOGV("  putchar register result", info->putchar_result);
	LOGV("  kprintf register result", info->kprintf_result);
	LOGV("  putchar chars", info->putchar_chars);
	LOGV("  kprintf calls", info->kprintf_calls);
	LOGV("  records pending", info->records_pending);
}

/* Prints once through each user path and records how many characters the
 * capture saw, as evidence in rrc.log that the wiring is live. */
static void capture_selftest(void)
{
	static const char via_stdout[] = "[rrc] console capture: stdout path\n";
	RrcTtyInfo a, b, c;
	SceUID out;
	int w;

	if (!capture_linked(&a))
		return;
	sceClibPrintf("[rrc] console capture: sceClibPrintf path\n");
	capture_linked(&b);
	out = sceKernelGetStdout();
	w = out >= 0 ? sceIoWrite(out, via_stdout, sizeof(via_stdout) - 1) : out;
	capture_linked(&c);

	LOGV("selftest sceClibPrintf chars captured", b.putchar_chars - a.putchar_chars);
	LOGV("selftest stdout write result", w);
	LOGV("selftest stdout chars captured", c.putchar_chars - b.putchar_chars);
}

/* Socket of the session that completed PROTO_LIST; the status thread pushes
 * console lines on it. -1 when no session is up. */
static volatile int g_con_sock = -1;
static unsigned char g_push_tx[TXBUF];

/* ------------------------------------------------------- sleep and wake-up
 *
 * Sleep ends every connection. While the console is suspended the PC gives up on its
 * sessions, but a session that only waits for requests never finds out: its receive
 * timeout reads as idle, so it keeps its slot for good, and a console push to it can hold
 * the send lock while TCP retransmits to a PC that no longer answers. The listeners were
 * made once at start, too, and never replaced. After a few sleeps nothing could connect.
 *
 * Now a wake-up (power callback) or the Wi-Fi coming back (SceNetCtl) runs net_reset(),
 * which starts afresh: every session is ended (its slot frees and the PC reconnects), and
 * the TCP and UDP listeners are reopened (g_net_epoch). The listeners are non-blocking and
 * polled, so their threads always see the new epoch; they also reopen by themselves when
 * their socket keeps failing (SceNet has SCE_NET_ERROR_ERESUME for sockets from before). */
#define SEND_TIMEOUT_US  (10 * 1000 * 1000)
#define LISTEN_POLL_US   (100 * 1000)
#define EVICT_IDLE_US    (10ull * 1000 * 1000)

static volatile unsigned int g_net_epoch;
static volatile int g_srv_sock = -1;           /* the listeners, published for net_reset() */
static volatile int g_udp_sock = -1;

/* The console session on socket s is broken (a push to it failed): end it so its slot
 * frees. Only while it is still g_con_sock: that is cleared, under the slot lock, before
 * its socket is closed, so the number cannot belong to a newer session by then. */
static void session_drop(int s)
{
	int i;

	slot_lock();
	if (g_con_sock == s) {
		g_con_sock = -1;
		for (i = 0; i < MAX_CONN; i++)
			if (g_slot_busy[i] && g_slot_sock[i] == s)
				session_kill_locked(i);
	}
	slot_unlock();
}

static void net_reset(void)
{
	int i;

	slot_lock();
	g_net_epoch++;
	g_con_sock = -1;
	for (i = 0; i < MAX_CONN; i++)
		session_kill_locked(i);
	/* The listeners are non-blocking, but if a socket ignored that, the abort still ends
	 * the wait so its thread sees the new epoch. */
	if (g_srv_sock >= 0)
		sceNetSocketAbort(g_srv_sock, 0);
	if (g_udp_sock >= 0)
		sceNetSocketAbort(g_udp_sock, 0);
	slot_unlock();
}

static void listener_set(volatile int *pub, int s)
{
	slot_lock();
	*pub = s;
	slot_unlock();
}

static void listener_close(volatile int *pub, int s)
{
	slot_lock();
	*pub = -1;
	sceNetSocketClose(s);
	slot_unlock();
}

/* SceNet reports "nothing yet" on a non-blocking socket as EAGAIN, either as the return
 * value or through errno. */
static int would_block(int r)
{
	int e;

	/* 0x804101A3 (errno 163, unnamed in VitaSDK) is also "nothing pending" for accept:
	 * vdbtcp's polled listener skips it the same way. */
	if (r == (int)SCE_NET_ERROR_EAGAIN || r == (int)0x804101A3)
		return 1;
	e = sceNetErrnoLoc() ? *sceNetErrnoLoc() : 0;
	return e == SCE_NET_EAGAIN || e == 163;
}

/* SYSTEM_RESUMING and SYSTEM_RESUME are the wake-up from sleep. APP_RESUME is not used: it
 * also comes when an application returns to the foreground, which must not drop anything. */
#define WAKE_EVENTS (SCE_POWER_CB_SYSTEM_RESUMING | SCE_POWER_CB_SYSTEM_RESUME)
static unsigned int g_power_events;            /* written by power_cb, on wake_thread */

static int power_cb(int notify_id, int notify_count, int power_info, void *common)
{
	(void)notify_id; (void)notify_count; (void)common;
	g_power_events |= (unsigned int)power_info & WAKE_EVENTS;
	return 0;
}

/* SceNetCtl is imported weakly, like SceNet: SceShell loads it after taiHEN injects the
 * plugin. Until the loader resolves the import the stub holds the toolchain's placeholder,
 * not an ARM instruction (the same test as capture_linked). */
static int netctl_linked(void)
{
	const unsigned int *stub = (const unsigned int *)((unsigned int)&sceNetCtlInetGetState & ~1u);

	return (stub[0] & 0xf0000000u) == 0xe0000000u;
}

/* Two signals start the network afresh (net_reset): the power callback on a wake-up, and
 * SceNetCtl's state coming back to CONNECTED after the Wi-Fi dropped, which is what the
 * other SceShell servers (vitacompanion, vdbtcp) rely on. A wake-up usually gives both, a
 * few seconds apart; the second reset only finds the fresh listeners and reopens them. */
static int wake_thread(SceSize args, void *argp)
{
	SceUID cb;
	int r, netctl = 0, state = 0, last = -1;
	unsigned int ticks = 0;

	(void)args; (void)argp;

	cb = sceKernelCreateCallback("rrc_power", 0, power_cb, 0);
	r = cb >= 0 ? scePowerRegisterCallback(cb) : cb;
	if (r < 0) {
		LOGV("power callback failed - wake-up not seen, only Wi-Fi reconnects", r);
		if (cb >= 0)
			sceKernelDeleteCallback(cb);
		cb = -1;
	} else {
		LOG("power callback registered");
	}
	/* Read only: SceShell owns netctl, the plugin never initialises it. */
	if (netctl_linked()) {
		r = sceNetCtlInetGetState(&state);
		if (r >= 0) {
			netctl = 1;
			last = state;
			LOGV("netctl state", state);
		} else {
			LOGV("netctl state unavailable - Wi-Fi reconnects not seen", r);
		}
	} else {
		LOG("netctl not linked - Wi-Fi reconnects not seen");
	}

	/* Callbacks run on this thread, inside the CB waits. */
	while (g_run) {
		sceKernelDelayThreadCB(200 * 1000);
		if (g_power_events) {
			unsigned int ev;

			/* One wake-up reports both events; collect them into one reset. */
			sceKernelDelayThreadCB(1000 * 1000);
			ev = g_power_events;
			g_power_events = 0;
			LOGV("woke from sleep: resetting the network, power events", ev);
			net_reset();
		}
		if (netctl && (++ticks % 5) == 0 && sceNetCtlInetGetState(&state) >= 0 &&
		    state != last) {
			LOGV("netctl state", state);
			if (state == SCE_NETCTL_STATE_CONNECTED) {
				LOG("Wi-Fi connected again: resetting the network");
				net_reset();
			}
			last = state;
		}
	}
	if (cb >= 0) {
		scePowerUnregisterCallback(cb);
		sceKernelDeleteCallback(cb);
	}
	return sceKernelExitDeleteThread(0);
}

static unsigned int app(char *dst, unsigned int n, const char *s)
{
	unsigned int l = kstrlen(s);

	kmemcpy(dst + n, s, l);
	return n + l;
}

/* Any file the user drops lines into shows up in Console Output. Point a log
 * writer at this path and its output streams to the PC live. */
#define TAILPATH "ux0:data/rrc_console.txt"
static SceOff g_tail_off;
static char g_tail_buf[512];

static void tail_file(int sock)
{
	SceUID fd = sceIoOpen(TAILPATH, SCE_O_RDONLY, 0);
	SceOff sz;
	int r;

	if (fd < 0)
		return;
	sz = sceIoLseek(fd, 0, SCE_SEEK_END);
	if (sz < g_tail_off)          /* truncated or replaced: start over */
		g_tail_off = 0;
	if (sz == g_tail_off) {
		sceIoClose(fd);
		return;
	}
	sceIoLseek(fd, g_tail_off, SCE_SEEK_SET);
	while ((r = sceIoRead(fd, g_tail_buf, sizeof(g_tail_buf) - 1)) > 0) {
		g_tail_buf[r] = 0;
		g_tail_off += r;
		if (ttyp_send(sock, g_push_tx, g_tail_buf) < 0) {
			session_drop(sock);
			break;
		}
		if (g_con_sock < 0)
			break;
	}
	sceIoClose(fd);
}

/* Drains rrc_tty.skprx's capture into the live session as TTYP frames, and
 * forwards anything appended to TAILPATH. Same single-session model as the
 * rest of the plugin: g_con_sock is the session that completed PROTO_LIST.
 * Output captured before a tool connects (boot included) waits in the kernel
 * ring and is delivered once g_con_sock is set. */
static int status_thread(SceSize args, void *argp)
{
	unsigned int loops = 0;

	(void)args; (void)argp;

	while (g_run) {
		int s = g_con_sock;
		int n = 0, i;

		/* Perform a pending Neighborhood power operation once the host has
		 * had a few seconds to poll POWER_STATUS and see the OFF/SUSPENDED
		 * transition. Runs regardless of session state so the reboot still
		 * happens if the host has already dropped the connection. */
		if (g_power_op != 0xffffffffu &&
		    sceKernelGetProcessTimeWide() >= g_power_at) {
			unsigned int op = g_power_op;

			g_power_op = 0xffffffffu;
			LOGV("performing power op", op);
			if (op == 0x81)
				scePowerRequestSuspend();
			else if (op == 0x80)
				scePowerRequestStandby();
			else
				scePowerRequestColdReset();
		}

		if (s < 0) {
			sceKernelDelayThread(200 * 1000);
			continue;
		}
		if (g_capture) {
			n = rrcTtyRead(g_tty_rec, TTY_BATCH);
			for (i = 0; i < n; i++) {
				if (g_tty_rec[i].source == RRC_TTY_SOURCE_USER)
					note_pid((SceUID)g_tty_rec[i].pid);
				if (ttyp_send_rec(s, g_push_tx, &g_tty_rec[i]) < 0) {
					/* A failed send leaves the stream mid-frame: the session is
					 * over. Ending it frees its slot; the next session to
					 * complete PROTO_LIST takes the console over. */
					session_drop(s);
					break;
				}
				if (g_con_sock < 0)
					break;
			}
		}
		if ((loops++ % 40) == 0)
			tail_file(s);
		if (n < TTY_BATCH)
			sceKernelDelayThread(50 * 1000);
	}
	return sceKernelExitDeleteThread(0);
}
static int g_slot_arg[MAX_CONN];

static int conn_thread(SceSize args, void *argp)
{
	int slot = *(int *)argp;
	int sock = g_slot_sock[slot];

	serve(sock, slot);
	slot_lock();
	if (g_con_sock == sock)
		g_con_sock = -1;
	sceNetSocketClose(sock);
	g_slot_sock[slot] = -1;
	g_slot_kill[slot] = 0;
	g_slot_busy[slot] = 0;
	slot_unlock();
	return sceKernelExitDeleteThread(0);
}

/* A free slot for socket cs, marked busy; -1 if none frees within 2 s. When every slot is
 * taken, the session silent longest (at least EVICT_IDLE_US) is ended to make room: a
 * session whose PC went away without a word (network dropped, PC asleep) never ends on its
 * own, and eight of them locked every tool out. */
static int slot_claim(int cs)
{
	SceUInt64 now = sceKernelGetProcessTimeWide();
	int i, slot, victim = -1, tries;

	for (tries = 0; tries < 40; tries++) {
		slot_lock();
		for (slot = 0; slot < MAX_CONN; slot++)
			if (!g_slot_busy[slot])
				break;
		if (slot < MAX_CONN) {
			g_slot_busy[slot] = 1;
			g_slot_sock[slot] = cs;
			g_slot_kill[slot] = 0;
			g_slot_rx_at[slot] = now;
			slot_unlock();
			return slot;
		}
		if (tries == 0) {
			for (i = 0; i < MAX_CONN; i++)
				if (!g_slot_kill[i] && now - g_slot_rx_at[i] >= EVICT_IDLE_US &&
				    (victim < 0 || g_slot_rx_at[i] < g_slot_rx_at[victim]))
					victim = i;
			if (victim >= 0)
				session_kill_locked(victim);
		}
		slot_unlock();
		if (tries == 0 && victim >= 0)
			LOGV("all connection slots busy - ending the longest idle session, slot", victim);
		sceKernelDelayThread(50 * 1000);
	}
	return -1;
}

static int udp_open(int loud)
{
	int s, r, opt = 1;
	SceNetSockaddrIn sa;

	s = sceNetSocket("rrc_udp", SCE_NET_AF_INET, SCE_NET_SOCK_DGRAM, 0);
	if (s < 0) {
		if (loud)
			LOGV("udp socket failed", s);
		return -1;
	}
	sceNetSetsockopt(s, SCE_NET_SOL_SOCKET, SCE_NET_SO_REUSEADDR, &opt, sizeof(opt));
	sceNetSetsockopt(s, SCE_NET_SOL_SOCKET, SCE_NET_SO_BROADCAST, &opt, sizeof(opt));
	sceNetSetsockopt(s, SCE_NET_SOL_SOCKET, SCE_NET_SO_NBIO, &opt, sizeof(opt));

	kmemset(&sa, 0, sizeof(sa));
	sa.sin_family = SCE_NET_AF_INET;
	sa.sin_port = hton16(PORT);
	sa.sin_addr.s_addr = SCE_NET_INADDR_ANY;
	r = sceNetBind(s, (SceNetSockaddr *)&sa, sizeof(sa));
	if (r < 0) {
		if (loud)
			LOGV("udp bind failed", r);
		sceNetSocketClose(s);
		return -1;
	}
	LOG("udp listening");
	return s;
}

static int udp_thread(SceSize args, void *argp)
{
	int s = -1, fails = 0, loud = 1;
	unsigned int epoch = 0;

	(void)args; (void)argp;

	while (g_run) {
		SceNetSockaddrIn from;
		unsigned int flen = sizeof(from);
		int r;
		unsigned short flags, node;
		unsigned int proto, arg, seq;

		if (s >= 0 && epoch != g_net_epoch) {
			listener_close(&g_udp_sock, s);
			s = -1;
			LOG("udp socket reopened after wake-up");
		}
		if (s < 0) {
			epoch = g_net_epoch;
			s = udp_open(loud);
			if (s < 0) {
				loud = 0;                   /* log the first failure of a run only */
				sceKernelDelayThread(2 * 1000 * 1000);
				continue;
			}
			listener_set(&g_udp_sock, s);
			loud = 1;
			fails = 0;
		}

		kmemset(&from, 0, sizeof(from));
		r = sceNetRecvfrom(s, g_udp_rx, UDPBUF, 0,
		                   (SceNetSockaddr *)&from, &flen);
		if (r < 0) {
			if (would_block(r)) {
				sceKernelDelayThread(LISTEN_POLL_US);
				continue;
			}
			/* Until 22/09 an error here was retried at once, forever: a socket
			 * killed by sleep spun this thread and discovery never came back. */
			if (fails++ == 0)
				LOGV("udp receive failed", r);
			if (fails >= 3) {
				LOG("udp socket keeps failing - reopening it");
				listener_close(&g_udp_sock, s);
				s = -1;
			}
			sceKernelDelayThread(1000 * 1000);
			continue;
		}
		fails = 0;
		if (r < 28)
			continue;
		if (g_udp_rx[3] != MARKER)
			continue;
		flags = get16(g_udp_rx + 4);
		node  = get16(g_udp_rx + 6);
		proto = get32(g_udp_rx + 8);
		if (proto != PROTO_TSMP)
			continue;
		if (g_udp_rx[16] != 1 || g_udp_rx[17] != 2)
			continue;
		arg = get32(g_udp_rx + 20);
		seq = get32(g_udp_rx + 24);

		mkhdr(g_udp_tx, 12 + 4, flags, node, proto);
		g_udp_tx[16] = 1; g_udp_tx[17] = 3;
		put16(g_udp_tx + 18, 0);
		put32(g_udp_tx + 20, arg);
		put32(g_udp_tx + 24, seq);
		kmemcpy(g_udp_tx + 28, g_udp_rx + 28, 4);
		sceNetSendto(s, g_udp_tx, 16 + 12 + 4, 0,
		             (SceNetSockaddr *)&from, flen);
		LOG("udp discovery answered");
	}
	if (s >= 0)
		listener_close(&g_udp_sock, s);
	return sceKernelExitDeleteThread(0);
}

static int tcp_listen_open(int loud)
{
	int srv, r, opt = 1;
	SceNetSockaddrIn sa;

	srv = sceNetSocket("rrc_tcp", SCE_NET_AF_INET, SCE_NET_SOCK_STREAM, 0);
	if (srv < 0) {
		if (loud)
			LOGV("tcp socket failed", srv);
		return -1;
	}
	sceNetSetsockopt(srv, SCE_NET_SOL_SOCKET, SCE_NET_SO_REUSEADDR,
	                 &opt, sizeof(opt));
	sceNetSetsockopt(srv, SCE_NET_SOL_SOCKET, SCE_NET_SO_NBIO, &opt, sizeof(opt));

	kmemset(&sa, 0, sizeof(sa));
	sa.sin_family = SCE_NET_AF_INET;
	sa.sin_port = hton16(PORT);
	sa.sin_addr.s_addr = SCE_NET_INADDR_ANY;
	r = sceNetBind(srv, (SceNetSockaddr *)&sa, sizeof(sa));
	if (r < 0) {
		if (loud)
			LOGV("tcp bind failed", r);
		sceNetSocketClose(srv);
		return -1;
	}
	r = sceNetListen(srv, MAX_CONN);
	if (r < 0) {
		if (loud)
			LOGV("tcp listen failed", r);
		sceNetSocketClose(srv);
		return -1;
	}
	LOG("tcp listening on 8540");
	return srv;
}

static int main_thread(SceSize args, void *argp)
{
	int srv = -1, tries = 0, fails = 0, loud = 1;
	unsigned int epoch = 0;
	SceUID thid;

	(void)args; (void)argp;

	/* Let SceShell finish starting and bring the network up. */
	sceKernelDelayThread(20 * 1000 * 1000);
	LOG("--- rrc user plugin start ---");
	capture_flag_clear();                   /* a flag left by a crash would keep a game recording */
	read_device_info();
	LOGV("sw version word", g_sw.version);
	{
		char line[64];
		unsigned int ln = app(line, 0, "target name ");

		ln = app(line, ln, target_name());
		line[ln] = 0;
		LOG(line);
	}

	g_send_mtx = sceKernelCreateMutex("rrc_send", 0, 0, 0);
	g_slot_mtx = sceKernelCreateMutex("rrc_slot", 0, 0, 0);
	g_dbg_mtx = sceKernelCreateMutex("rrc_dbg", 0, 0, 0);
	g_drfp_sema = sceKernelCreateSema("rrc_drfp", 0, 0, 1, 0);
	if (pa_linked()) {
		RrcPaInfo info;

		LOG("rrc_pa capture linked - Razor CPU trace available");
		if (rrcPaGetInfo(&info) >= 0)
			LOGV("  rrc_pa ring records", info.ring_capacity);
	} else if (g_pa_version) {
		LOGV("rrc_pa.skprx is a different version - Razor CPU trace unavailable; it reports",
		     g_pa_version);
		LOGV("  this plugin needs", RRC_PA_VERSION);
	} else {
		LOG("rrc_pa.skprx not loaded - Razor CPU trace unavailable");
	}

	{
		RrcTtyInfo info;

		g_capture = capture_linked(&info);
		if (g_capture) {
			log_capture(&info);
			capture_selftest();
		} else {
			LOG("rrc_tty.skprx not loaded - console capture off");
		}
	}

	/* SceNet is imported WEAKLY: when taiHEN injects a *main plugin, SceShell
	 * has not loaded the network library yet, and a strong import makes the
	 * module load fail outright with "Library not found: [SceNet, ver=1]".
	 * Pull it in here, before any socket call. */
	{
		int r = sceSysmoduleLoadModule(SCE_SYSMODULE_NET);

		LOGV("sysmodule net load", r);
	}

	/* Wait until the shell's network stack is initialised; never init it
	 * ourselves, that would fight with SceShell. */
	while (g_run && tries < 120) {
		if (sceNetShowNetstat() != SCE_NET_ERROR_ENOTINIT)
			break;
		tries++;
		sceKernelDelayThread(2 * 1000 * 1000);
	}
	LOGV("net ready after tries", tries);

	thid = sceKernelCreateThread("rrc_udp", udp_thread, 0x40, 0x4000, 0, 0, 0);
	if (thid >= 0)
		sceKernelStartThread(thid, 0, 0);
	thid = sceKernelCreateThread("rrc_stat", status_thread, 0x40, 0x4000, 0, 0, 0);
	if (thid >= 0)
		sceKernelStartThread(thid, 0, 0);
	thid = sceKernelCreateThread("rrc_wake", wake_thread, 0x40, 0x4000, 0, 0, 0);
	if (thid >= 0)
		sceKernelStartThread(thid, 0, 0);

	/* The listener is non-blocking and polled: this thread never waits inside a socket
	 * call, so it sees a wake-up (g_net_epoch) at once and reopens the listener, and it
	 * also reopens it when accept keeps failing. */
	while (g_run) {
		SceNetSockaddrIn cli;
		unsigned int clen = sizeof(cli);
		int cs, slot;

		if (srv >= 0 && epoch != g_net_epoch) {
			listener_close(&g_srv_sock, srv);
			srv = -1;
			LOG("tcp listener reopened after wake-up");
		}
		if (srv < 0) {
			epoch = g_net_epoch;
			srv = tcp_listen_open(loud);
			if (srv < 0) {
				loud = 0;                   /* log the first failure of a run only */
				sceKernelDelayThread(2 * 1000 * 1000);
				continue;
			}
			listener_set(&g_srv_sock, srv);
			loud = 1;
			fails = 0;
		}

		kmemset(&cli, 0, sizeof(cli));
		cs = sceNetAccept(srv, (SceNetSockaddr *)&cli, &clen);
		if (cs < 0) {
			if (would_block(cs)) {
				sceKernelDelayThread(LISTEN_POLL_US);
				continue;
			}
			if (fails++ == 0)
				LOGV("tcp accept failed", cs);
			if (fails >= 3) {
				LOG("tcp listener keeps failing - reopening it");
				listener_close(&g_srv_sock, srv);
				srv = -1;
			}
			sceKernelDelayThread(1000 * 1000);
			continue;
		}
		fails = 0;
		/* psp2tm opens probe connections that never send anything. Without a
		 * receive timeout those sit in serve() forever and leak a slot each,
		 * which starves the real tools (seen as "greeting read failed" plus
		 * tools timing out). Reap idle sockets instead. SceNet takes the
		 * timeouts as an int in microseconds, not a timeval. The send timeout
		 * keeps a vanished PC from holding the send lock (SEND_TIMEOUT_US).
		 * The socket may inherit the listener's non-blocking mode; serve()
		 * needs a blocking one. */
		{
			int idle_timeout = 45 * 1000 * 1000, send_timeout = SEND_TIMEOUT_US, off = 0;

			sceNetSetsockopt(cs, SCE_NET_SOL_SOCKET, SCE_NET_SO_NBIO, &off, sizeof(off));
			sceNetSetsockopt(cs, SCE_NET_SOL_SOCKET, SCE_NET_SO_RCVTIMEO,
			                 &idle_timeout, sizeof(idle_timeout));
			sceNetSetsockopt(cs, SCE_NET_SOL_SOCKET, SCE_NET_SO_SNDTIMEO,
			                 &send_timeout, sizeof(send_timeout));
		}
		slot = slot_claim(cs);
		if (slot < 0) {
			LOG("no free connection slot - dropping");
			sceNetSocketClose(cs);
			continue;
		}
		g_slot_arg[slot] = slot;
		thid = sceKernelCreateThread("rrc_conn", conn_thread, 0x40,
		                             0x8000, 0, 0, 0);
		if (thid < 0) {
			slot_lock();
			sceNetSocketClose(cs);
			g_slot_sock[slot] = -1;
			g_slot_busy[slot] = 0;
			slot_unlock();
			continue;
		}
		sceKernelStartThread(thid, sizeof(int), &g_slot_arg[slot]);
	}
	if (srv >= 0)
		listener_close(&g_srv_sock, srv);
	return sceKernelExitDeleteThread(0);
}

void _start() __attribute__((weak, alias("module_start")));

int module_start(SceSize argc, const void *args)
{
	SceUID thid;
	int i;

	(void)argc; (void)args;

	for (i = 0; i < MAX_CONN; i++) {
		g_slot_busy[i] = 0;
		g_slot_sock[i] = -1;
	}
	thid = sceKernelCreateThread("rrc_main", main_thread, 0x40, 0x4000,
	                             0, 0, 0);
	if (thid >= 0)
		sceKernelStartThread(thid, 0, 0);
	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
	(void)argc; (void)args;
	g_run = 0;
	return SCE_KERNEL_STOP_SUCCESS;
}
