/*
 * retail_razorconnect.skprx
 *
 * Makes a retail PS Vita (HENkaku / taiHEN) answer Sony's Target Manager /
 * Neighborhood on TCP+UDP port 8540, so the console shows up as a DevKit.
 *
 * This is a direct port of the proven PC mock (tools/mock16.py variant M),
 * whose protocol was recovered from psp2tm.exe. See ../docs/PROTOCOL.md.
 *
 * Frame:  u24 total_len | u8 0x40 | u16 flags | u16 node | u32 proto | u32 resv
 * TSMP payload (proto 0x2000): u8 type, u8 code, u16 pad, u32 arg, u32 seq, body
 * NETMP payload (proto 0x1000): u8 code, u8 pad, u16 pad, body        (no arg/seq)
 * CPUP payload (proto 0x3000): like TSMP but a single code byte
 *
 * Deliberately conservative: no hooks, no patches, no kernel structures touched.
 * It only creates threads and sockets. Everything is retried and nothing is
 * fatal, so a failure degrades to "does nothing" rather than breaking boot.
 */

#include <psp2kern/kernel/modulemgr.h>
#include <psp2kern/kernel/threadmgr.h>
#include <psp2kern/kernel/debug.h>
#include <psp2kern/kernel/aimgr.h>
#include <psp2kern/kernel/sysmem.h>
#include <psp2kern/netps.h>
#include <psp2common/net.h>

/* Kernel printf lands in the system log, which net_logging_mgr forwards to the
 * PC (PSVITA_Logs.log). This is the only observability we get on-device. */
#define LOG(...) ksceKernelPrintf("[rrc] " __VA_ARGS__)

#define PORT            8540
#define PROTO_NETMP     0x1000
#define PROTO_TSMP      0x2000
#define PROTO_CPUP      0x3000
#define MAXPAY          0x10800
#define MARKER          0x40
#define HANDSHAKE_MAGIC 0x15A3F8E1

/* Hardware id this target advertises. Any value works: psp2tm performs no
 * authentication of the peer. Shown in Neighborhood's HardwareId column. */
#define HWID            1444602

#define MAX_CONN        4
#define RXBUF           2048
#define TXBUF           1024

/* ------------------------------------------------------------------ utils */

/* GCC turns byte loops back into calls to these even with -ffreestanding,
 * and there is no libc in a kernel module, so provide them ourselves. */
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

unsigned int strlen(const char *s)
{
	unsigned int n = 0;
	while (s[n])
		n++;
	return n;
}

static void kmemset(void *d, int v, unsigned int n)
{
	unsigned char *p = (unsigned char *)d;
	while (n--)
		*p++ = (unsigned char)v;
}

static void kmemcpy(void *d, const void *s, unsigned int n)
{
	unsigned char *a = (unsigned char *)d;
	const unsigned char *b = (const unsigned char *)s;
	while (n--)
		*a++ = *b++;
}

static unsigned int kstrlen(const char *s)
{
	unsigned int n = 0;
	while (s[n])
		n++;
	return n;
}

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

/* host->network for a 16-bit port, without sceNetHtons (user-side only) */
static unsigned short hton16(unsigned short v)
{
	return (unsigned short)((v >> 8) | (v << 8));
}

static unsigned int align4(unsigned int n)
{
	return (n + 3u) & ~3u;
}

/* ----------------------------------------------------- real device info */

/* Model, from the security/auth manager rather than guessed. */
static const char *device_model(void)
{
	if (ksceSblAimgrIsTool())
		return "PSP2 DevKit";
	if (ksceSblAimgrIsTest())
		return "PSP2 TestKit";
	if (ksceSblAimgrIsDolce())
		return "PlayStation TV";
	if (ksceSblAimgrIsVITA())
		return "PS Vita";
	return "PSP2";
}

/* Firmware version string, built from the running system software version.
 * Format matches what Neighborhood's SDK column expects: "M.MMM.BBB". */
static char g_fwstr[16];

static void build_fw_string(unsigned int v)
{
	/* v is packed 0xMMmmbbbb, e.g. 0x03650000 -> "3.650.000" */
	unsigned int maj = (v >> 24) & 0xff;
	unsigned int min = (v >> 16) & 0xff;
	unsigned int bld = v & 0xffff;
	int i = 0;

	g_fwstr[i++] = (char)('0' + (maj % 10));
	g_fwstr[i++] = '.';
	g_fwstr[i++] = (char)('0' + ((min >> 4) & 0xf));
	g_fwstr[i++] = (char)('0' + (min & 0xf));
	g_fwstr[i++] = '0';
	g_fwstr[i++] = '.';
	g_fwstr[i++] = (char)('0' + ((bld / 100) % 10));
	g_fwstr[i++] = (char)('0' + ((bld / 10) % 10));
	g_fwstr[i++] = (char)('0' + (bld % 10));
	g_fwstr[i] = 0;
}

/* --------------------------------------------------------------- framing */

/* Write the 16-byte DECI frame header. Returns header size. */
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

/* One named-value record, as psp2tm's FUN_1400cdeb0 walks them:
 *   u32 record_total_length
 *   u32 name_length (INCLUDING the NUL)
 *   name bytes, padded to 4
 *   u16 value_length, u16 value_type (1 = binary, 2 = string)
 *   value bytes, padded to 4
 * Returns bytes written. */
static unsigned int nv_record(unsigned char *out, const char *name,
                              const unsigned char *val, unsigned int vlen,
                              unsigned short vtype)
{
	unsigned int nlen = kstrlen(name) + 1;      /* NUL included */
	unsigned int npad = align4(nlen);
	unsigned int vpad = align4(vlen);
	unsigned int body = npad + 4 + vpad;
	unsigned int off = 0;

	put32(out + off, 8 + body); off += 4;
	put32(out + off, nlen);     off += 4;
	kmemcpy(out + off, name, nlen);
	kmemset(out + off + nlen, 0, npad - nlen);
	off += npad;
	put16(out + off, (unsigned short)vlen);     off += 2;
	put16(out + off, vtype);                    off += 2;
	kmemcpy(out + off, val, vlen);
	kmemset(out + off + vlen, 0, vpad - vlen);
	off += vpad;
	return off;
}

/* Parse the key names a HW_INFO / SW_INFO / GET_SETTINGS command asks for:
 *   u32 count, then count x { u32 name_len_incl_nul; name; pad to 4 }
 * Returns count; fills offs[] with offsets of each name within body. */
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

/* ------------------------------------------------------------ socket I/O */

/* Only Recvfrom/Sendto are exported to kernel (there is no ksceNetRecv/Send),
 * and passing NULL for the address arguments made the first build fail silently,
 * so always hand them a real buffer. */
static int sock_send(int s, const void *buf, unsigned int len)
{
	const unsigned char *p = (const unsigned char *)buf;
	unsigned int sent = 0;

	while (sent < len) {
		int r = ksceNetSendto(s, p + sent, len - sent, 0, 0, 0);
		if (r <= 0) {
			LOG("sendto failed r=0x%08X (sent %u/%u)\n", r, sent, len);
			return -1;
		}
		sent += (unsigned int)r;
	}
	return 0;
}

/* Read exactly len bytes. Returns 0 on success, -1 on close/error. */
static int sock_recv_all(int s, void *buf, unsigned int len)
{
	unsigned char *p = (unsigned char *)buf;
	unsigned int got = 0;

	while (got < len) {
		SceNetSockaddrIn from;
		unsigned int flen = sizeof(from);
		int r;

		kmemset(&from, 0, sizeof(from));
		r = ksceNetRecvfrom(s, p + got, len - got, 0,
		                    (SceNetSockaddr *)&from, &flen);
		if (r <= 0) {
			LOG("recvfrom failed r=0x%08X (got %u/%u)\n", r, got, len);
			return -1;
		}
		got += (unsigned int)r;
	}
	return 0;
}

/* ------------------------------------------------------- TSMP responders */

/* Build the response body for TSMP (type, code). Returns body length. */
static unsigned int tsmp_body(unsigned char t, unsigned char c,
                              const unsigned char *body, unsigned int blen,
                              unsigned char *out)
{
	unsigned int off = 0;

	if (t == 1 && c == 0) {                 /* TARGET_LIST_CMD */
		put32(out + 0, 0);              /* result */
		put16(out + 4, 1);              /* count  */
		put16(out + 6, 0);
		put32(out + 8, HWID);
		return 12;
	}
	if (t == 1 && c == 2) {                 /* UDP_FIND_TARGET_CMD */
		put32(out, 0);
		return 4;
	}
	if (t == 2) {                           /* SELECT / DESELECT */
		put32(out, 0);
		return 4;
	}
	if (t == 3 && c == 0) {                 /* HW_INFO_CMD -> named values */
		unsigned int offs[8], lens[8];
		unsigned char cpid[16];
		int n, i;
		char name[64];

		n = parse_keys(body, blen, offs, lens, 8);
		if (n == 0) {
			/* default: answer CPID */
			put32(out + 0, 0);
			put16(out + 4, 1);
			put16(out + 6, 0);
			kmemset(cpid, 0, sizeof(cpid));
			put32(cpid + 0, HWID);
			put32(cpid + 4, 1);
			return 8 + nv_record(out + 8, "CPID", cpid, 16, 1);
		}
		put32(out + 0, 0);
		put16(out + 4, (unsigned short)n);
		put16(out + 6, 0);
		off = 8;
		for (i = 0; i < n; i++) {
			unsigned int l = lens[i] < sizeof(name) ? lens[i] : sizeof(name) - 1;

			kmemcpy(name, body + offs[i], l);
			name[l] = 0;
			/* CPID must be binary type 1, length 0x10 (FUN_14007a5d0) */
			kmemset(cpid, 0, sizeof(cpid));
			put32(cpid + 0, HWID);
			put32(cpid + 4, 1);
			off += nv_record(out + off, name, cpid, 16, 1);
		}
		return off;
	}
	if (t == 3 && c == 2) {                 /* SET_STICKY_NOTE */
		put32(out + 0, 0);
		put32(out + 4, 0);
		return 8;
	}
	if (t == 3 && c == 4) {                 /* SW_INFO_CMD */
		unsigned int offs[8], lens[8];
		int n, i;
		char name[64];
		const char *ver = g_fwstr[0] ? g_fwstr : "3.650.000";
		unsigned int verlen = kstrlen(ver) + 1;

		n = parse_keys(body, blen, offs, lens, 8);
		put32(out + 0, 0);
		put16(out + 4, (unsigned short)(n ? n : 1));
		put16(out + 6, 0);
		off = 8;
		if (n == 0)
			return off + nv_record(out + off, "SdkVersion",
			                       (const unsigned char *)ver,
			                       verlen, 2);
		for (i = 0; i < n; i++) {
			unsigned int l = lens[i] < sizeof(name) ? lens[i] : sizeof(name) - 1;

			kmemcpy(name, body + offs[i], l);
			name[l] = 0;
			off += nv_record(out + off, name,
			                 (const unsigned char *)ver, verlen, 2);
		}
		return off;
	}
	if (t == 3 && c == 6) {                 /* GET_EXPIRY_TIME */
		put32(out + 0, 0);
		put32(out + 4, 0xFFFFFFFFu);
		return 8;
	}
	if (t == 3 && c == 8) {                 /* GET_USB_INFO: 0x30 + blob */
		kmemset(out, 0, 0x30);
		put32(out + 0, 0);
		put32(out + 4, 0x30 - 4);       /* self-relative offset */
		put32(out + 0x30, 8);
		put32(out + 0x34, 0);
		return 0x38;
	}
	if (t == 4 && c == 0) {                 /* POWER_STATUS */
		put32(out + 0, 0);
		put32(out + 4, 1);              /* powered on */
		return 8;
	}
	if (t == 4) {                           /* POWER_CONTROL / UPDATE_ACTIVATION */
		put32(out, 0);
		return 4;
	}
	if (t == 5 && (c == 0 || c == 2)) {     /* GET_SETTINGS */
		unsigned int offs[8], lens[8];
		int n, i;
		char name[128];
		const char *devname = device_model();
		unsigned int dlen = kstrlen(devname) + 1;

		n = parse_keys(body, blen, offs, lens, 8);
		put32(out + 0, 0);
		put16(out + 4, (unsigned short)n);
		put16(out + 6, 0);
		off = 8;
		for (i = 0; i < n; i++) {
			unsigned int l = lens[i] < sizeof(name) ? lens[i] : sizeof(name) - 1;

			kmemcpy(name, body + offs[i], l);
			name[l] = 0;
			off += nv_record(out + off, name,
			                 (const unsigned char *)devname, dlen, 2);
		}
		return off;
	}
	if (t == 5 && c == 8) {                 /* GET_SETTINGS_XML */
		static const char xml[] = "<?xml version=\"1.0\"?><settings/>";
		unsigned int xl = sizeof(xml);

		put32(out + 0, 0);
		put32(out + 4, xl);
		kmemcpy(out + 8, xml, xl);
		kmemset(out + 8 + xl, 0, align4(xl) - xl);
		return 8 + align4(xl);
	}
	put32(out, 0);
	return 4;
}

/* NETMP protocol descriptors advertised in PROTO_LIST_RES.
 * entry: u32 proto, u32 limit, u32 unused, u16 node (MUST be non-zero), u16 pad
 * The node values become the header node for each protocol's later frames. */
static const unsigned int g_proto_num[3]  = { PROTO_NETMP, PROTO_TSMP, PROTO_CPUP };
static const unsigned short g_proto_node[3] = { 0x0011, 0x0022, 0x0033 };

static unsigned int netmp_body(unsigned char code, unsigned char *out,
                               unsigned char *rescode)
{
	unsigned int i, off;

	switch (code) {
	case 0:                                  /* CONNECT_CMD */
		*rescode = 1;
		put32(out, 0);
		return 4;
	case 2:                                  /* DISCONNECT_CMD */
		*rescode = 3;
		put32(out, 0);
		return 4;
	case 4:                                  /* REGISTER_CMD */
		*rescode = 5;
		put32(out + 0, 0);
		put32(out + 4, 0);
		return 8;
	case 6:                                  /* UNREGISTER_CMD */
		*rescode = 7;
		put32(out + 0, 0);
		put32(out + 4, 0);
		return 8;
	case 8:                                  /* REGISTERED_LIST_CMD */
		*rescode = 9;
		put32(out + 0, 0);
		put32(out + 4, 0);
		return 8;
	case 10:                                 /* PROTO_LIST_CMD */
		*rescode = 11;
		put32(out + 0, 0);
		put32(out + 4, 3);
		off = 8;
		for (i = 0; i < 3; i++) {
			put32(out + off + 0, g_proto_num[i]);
			put32(out + off + 4, MAXPAY);
			put32(out + off + 8, 0);
			put16(out + off + 12, g_proto_node[i]);
			put16(out + off + 14, 0);
			off += 16;
		}
		return off;
	case 12:
		*rescode = 13;
		put32(out, 0);
		return 4;
	case 14:
		*rescode = 15;
		put32(out, 0);
		return 4;
	default:
		return 0;                        /* nothing to answer */
	}
}

/* ------------------------------------------------------- TCP connection */

/* Network buffers must live in a real allocated memory block, NOT in the
 * module's .bss or on a thread stack: ksceNetRecvfrom rejects those with
 * 0xC0022005 (observed on-device). Layout of the pool:
 *   [MAX_CONN] x (RXBUF + TXBUF)  then  UDPBUF rx + UDPBUF tx
 */
#define UDPBUF 1024
#define POOL_SIZE 0x8000

static SceUID g_pool_uid = -1;
static unsigned char *g_pool;

static unsigned char *slot_rx(int i) { return g_pool + i * (RXBUF + TXBUF); }
static unsigned char *slot_tx(int i) { return g_pool + i * (RXBUF + TXBUF) + RXBUF; }
static unsigned char *udp_rx(void)   { return g_pool + MAX_CONN * (RXBUF + TXBUF); }
static unsigned char *udp_tx(void)   { return udp_rx() + UDPBUF; }

static int g_slot_busy[MAX_CONN];
static int g_slot_sock[MAX_CONN];
static int g_run = 1;

static void serve(int sock, int slot)
{
	unsigned char *rx = slot_rx(slot);
	unsigned char *tx = slot_tx(slot);
	unsigned char *hdr = rx;          /* header read into pool memory too */

	/* handshake: expect "DECI", answer big-endian magic + length + 56 bytes */
	LOG("serve slot=%d waiting for greeting\n", slot);
	if (sock_recv_all(sock, rx, 4) < 0) {
		LOG("greeting read failed\n");
		return;
	}
	LOG("greeting %02x %02x %02x %02x\n", rx[0], rx[1], rx[2], rx[3]);
	if (rx[0] != 'D' || rx[1] != 'E' || rx[2] != 'C' || rx[3] != 'I') {
		LOG("not DECI, dropping\n");
		return;
	}

	kmemset(tx, 0, 64);
	tx[0] = (unsigned char)((HANDSHAKE_MAGIC >> 24) & 0xff);   /* big-endian */
	tx[1] = (unsigned char)((HANDSHAKE_MAGIC >> 16) & 0xff);
	tx[2] = (unsigned char)((HANDSHAKE_MAGIC >> 8) & 0xff);
	tx[3] = (unsigned char)(HANDSHAKE_MAGIC & 0xff);
	tx[4] = 0; tx[5] = 0; tx[6] = 0; tx[7] = 0x40;             /* 0x40 BE */
	if (sock_send(sock, tx, 64) < 0) {
		LOG("handshake reply failed\n");
		return;
	}
	LOG("handshake sent, entering frame loop\n");

	while (g_run) {
		unsigned int len, proto, paylen, blen, rlen;
		unsigned short flags, node;
		unsigned char *pay;

		if (sock_recv_all(sock, hdr, 16) < 0)
			return;
		len = (unsigned int)hdr[0] | ((unsigned int)hdr[1] << 8) |
		      ((unsigned int)hdr[2] << 16);
		if (hdr[3] != MARKER || len < 16 || len > MAXPAY)
			return;
		paylen = len - 16;
		if (paylen > RXBUF - 16)
			return;                                     /* refuse oversize */
		/* header occupies rx[0..15]; payload goes after it */
		if (paylen && sock_recv_all(sock, rx + 16, paylen) < 0)
			return;

		flags = get16(hdr + 4);
		node  = get16(hdr + 6);
		proto = get32(hdr + 8);
		pay   = rx + 16;

		if (proto == PROTO_NETMP) {
			unsigned char code = paylen ? pay[0] : 0xff;
			unsigned char rescode = 0;
			unsigned int bl;

			bl = netmp_body(code, tx + 16 + 4, &rescode);
			if (bl == 0)
				continue;
			mkhdr(tx, 4 + bl, flags, node, proto);
			tx[16] = rescode;
			tx[17] = 0;
			put16(tx + 18, 0);
			if (sock_send(sock, tx, 16 + 4 + bl) < 0)
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
			kmemset(tx + 16 + 12, 0, bl);
			mkhdr(tx, 12 + bl, flags, node, proto);
			tx[16] = (unsigned char)(code + 1);
			tx[17] = 0;
			put16(tx + 18, 0);
			put32(tx + 20, arg);
			put32(tx + 24, seq);
			if (sock_send(sock, tx, 16 + 12 + bl) < 0)
				return;
			continue;
		}

		if (proto != PROTO_TSMP || paylen < 12)
			continue;

		{
			unsigned char t = pay[0], c = pay[1];
			unsigned int arg = get32(pay + 4);
			unsigned int seq = get32(pay + 8);

			if ((c & 1) || t == 6)
				continue;                   /* already a RES / notify */
			blen = paylen - 12;
			rlen = tsmp_body(t, c, pay + 12, blen, tx + 16 + 12);
			if (16 + 12 + rlen > TXBUF)
				continue;
			mkhdr(tx, 12 + rlen, flags, node, proto);
			tx[16] = t;
			tx[17] = (unsigned char)(c + 1);
			put16(tx + 18, 0);
			put32(tx + 20, arg);
			put32(tx + 24, seq);
			if (sock_send(sock, tx, 16 + 12 + rlen) < 0)
				return;
		}
	}
}

static int conn_thread(SceSize args, void *argp)
{
	int slot = *(int *)argp;

	serve(g_slot_sock[slot], slot);
	ksceNetClose(g_slot_sock[slot]);
	g_slot_sock[slot] = -1;
	g_slot_busy[slot] = 0;
	return ksceKernelExitDeleteThread(0);
}

/* ------------------------------------------------------------ UDP thread */

static int g_udp_logs;
static int g_acc_logs;

static int udp_thread(SceSize args, void *argp)
{
	int s;
	int opt = 1;
	SceNetSockaddrIn sa;

	(void)args; (void)argp;

	/* main_thread allocates the shared buffer pool; wait for it. */
	while (g_run && !g_pool)
		ksceKernelDelayThread(1000 * 1000);

	while (g_run) {
		s = ksceNetSocket("rrc_udp", SCE_NET_AF_INET, SCE_NET_SOCK_DGRAM, 0);
		if (s >= 0)
			break;
		ksceKernelDelayThread(5 * 1000 * 1000);
	}
	if (s < 0)
		return ksceKernelExitDeleteThread(0);

	ksceNetSetsockopt(s, SCE_NET_SOL_SOCKET, SCE_NET_SO_REUSEADDR, &opt, sizeof(opt));
	ksceNetSetsockopt(s, SCE_NET_SOL_SOCKET, SCE_NET_SO_BROADCAST, &opt, sizeof(opt));

	kmemset(&sa, 0, sizeof(sa));
	sa.sin_family = SCE_NET_AF_INET;
	sa.sin_port = hton16(PORT);
	sa.sin_addr.s_addr = SCE_NET_INADDR_ANY;
	if (ksceNetBind(s, (SceNetSockaddr *)&sa, sizeof(sa)) < 0) {
		ksceNetClose(s);
		return ksceKernelExitDeleteThread(0);
	}

	LOG("udp bound on %d, entering recv loop\n", PORT);

	while (g_run) {
		SceNetSockaddrIn from;
		unsigned int flen = sizeof(from);
		int r;
		unsigned short flags, node;
		unsigned int proto, arg, seq;

		kmemset(&from, 0, sizeof(from));
		r = ksceNetRecvfrom(s, udp_rx(), UDPBUF, 0,
		                    (SceNetSockaddr *)&from, &flen);
		if (g_udp_logs < 8) {
			g_udp_logs++;
			LOG("udp recvfrom -> r=0x%08X\n", r);
		}
		if (r < 0) {
			/* Do not spin at full speed on a persistent error. */
			ksceKernelDelayThread(1000 * 1000);
			continue;
		}
		if (r < 28)
			continue;
		if (udp_rx()[3] != MARKER)
			continue;
		flags = get16(udp_rx() + 4);
		node  = get16(udp_rx() + 6);
		proto = get32(udp_rx() + 8);
		if (proto != PROTO_TSMP)
			continue;
		if (udp_rx()[16] != 1 || udp_rx()[17] != 2)   /* UDP_FIND_TARGET_CMD */
			continue;
		arg = get32(udp_rx() + 20);
		seq = get32(udp_rx() + 24);

		mkhdr(udp_tx(), 12 + 4, flags, node, proto);
		udp_tx()[16] = 1;
		udp_tx()[17] = 3;                              /* UDP_FIND_TARGET_RES */
		put16(udp_tx() + 18, 0);
		put32(udp_tx() + 20, arg);
		put32(udp_tx() + 24, seq);
		kmemcpy(udp_tx() + 28, udp_rx() + 28, 4);      /* echo the counter */
		ksceNetSendto(s, udp_tx(), 16 + 12 + 4, 0,
		              (SceNetSockaddr *)&from, flen);
	}
	ksceNetClose(s);
	return ksceKernelExitDeleteThread(0);
}

/* ----------------------------------------------------------- main thread */

static int g_slot_arg[MAX_CONN];

static int main_thread(SceSize args, void *argp)
{
	int srv = -1;
	int opt = 1;
	SceNetSockaddrIn sa;
	SceUID udp_thid;

	(void)args; (void)argp;

	/* Let the system finish booting and the network stack come up. */
	ksceKernelDelayThread(25 * 1000 * 1000);
	LOG("main_thread up, model=%s\n", device_model());

	/* Network buffers must come from a real memory block: ksceNetRecvfrom
	 * rejects module .bss and thread stacks with 0xC0022005. */
	g_pool_uid = ksceKernelAllocMemBlock("rrc_pool",
	                                     SCE_KERNEL_MEMBLOCK_TYPE_KERNEL_RW,
	                                     POOL_SIZE, 0);
	if (g_pool_uid < 0) {
		LOG("pool alloc failed 0x%08X\n", g_pool_uid);
		return ksceKernelExitDeleteThread(0);
	}
	g_pool = 0;
	if (ksceKernelGetMemBlockBase(g_pool_uid, (void **)&g_pool) < 0 || !g_pool) {
		LOG("pool base failed\n");
		return ksceKernelExitDeleteThread(0);
	}
	kmemset(g_pool, 0, POOL_SIZE);
	LOG("pool ok at %p\n", g_pool);

	while (g_run) {
		srv = ksceNetSocket("rrc_tcp", SCE_NET_AF_INET, SCE_NET_SOCK_STREAM, 0);
		if (srv >= 0)
			break;
		ksceKernelDelayThread(5 * 1000 * 1000);
	}
	if (srv < 0)
		return ksceKernelExitDeleteThread(0);

	ksceNetSetsockopt(srv, SCE_NET_SOL_SOCKET, SCE_NET_SO_REUSEADDR,
	                  &opt, sizeof(opt));

	kmemset(&sa, 0, sizeof(sa));
	sa.sin_family = SCE_NET_AF_INET;
	sa.sin_port = hton16(PORT);
	sa.sin_addr.s_addr = SCE_NET_INADDR_ANY;

	while (g_run) {
		if (ksceNetBind(srv, (SceNetSockaddr *)&sa, sizeof(sa)) >= 0)
			break;
		ksceKernelDelayThread(5 * 1000 * 1000);
	}
	if (ksceNetListen(srv, MAX_CONN) < 0) {
		LOG("listen failed\n");
		ksceNetClose(srv);
		return ksceKernelExitDeleteThread(0);
	}
	LOG("listening on TCP %d\n", PORT);

	udp_thid = ksceKernelCreateThread("rrc_udp", udp_thread, 0x60, 0x2000,
	                                  0, 0, 0);
	if (udp_thid >= 0)
		ksceKernelStartThread(udp_thid, 0, 0);

	while (g_run) {
		SceNetSockaddrIn cli;
		unsigned int clen = sizeof(cli);
		int cs;
		int slot = -1, i;
		SceUID thid;

		kmemset(&cli, 0, sizeof(cli));
		cs = ksceNetAccept(srv, (SceNetSockaddr *)&cli, &clen);
		if (g_acc_logs < 8) {
			g_acc_logs++;
			LOG("accept -> 0x%08X\n", cs);
		}
		if (cs < 0) {
			ksceKernelDelayThread(1000 * 1000);
			continue;
		}
		LOG("accepted connection\n");
		for (i = 0; i < MAX_CONN; i++) {
			if (!g_slot_busy[i]) {
				slot = i;
				break;
			}
		}
		if (slot < 0) {                 /* all busy: drop politely */
			ksceNetClose(cs);
			continue;
		}
		g_slot_busy[slot] = 1;
		g_slot_sock[slot] = cs;
		g_slot_arg[slot] = slot;
		thid = ksceKernelCreateThread("rrc_conn", conn_thread, 0x60,
		                              0x4000, 0, 0, 0);
		if (thid < 0) {
			ksceNetClose(cs);
			g_slot_busy[slot] = 0;
			g_slot_sock[slot] = -1;
			continue;
		}
		ksceKernelStartThread(thid, sizeof(int), &g_slot_arg[slot]);
	}

	ksceNetClose(srv);
	return ksceKernelExitDeleteThread(0);
}

/* --------------------------------------------------------- module entry */

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

	thid = ksceKernelCreateThread("rrc_main", main_thread, 0x60, 0x4000,
	                              0, 0, 0);
	if (thid >= 0)
		ksceKernelStartThread(thid, 0, 0);

	/* Never fail: a failed kernel module start is what bootloops a console. */
	return SCE_KERNEL_START_SUCCESS;
}

int module_stop(SceSize argc, const void *args)
{
	(void)argc; (void)args;
	g_run = 0;
	return SCE_KERNEL_STOP_SUCCESS;
}
