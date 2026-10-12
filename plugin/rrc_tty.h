/*
 * rrc_tty.h -- the contract between rrc_tty.skprx (kernel, captures console
 * output) and retail_razorconnect.suprx (SceShell, pushes it to Target Manager).
 *
 * Streams and sources are the values the DevKit's TTYP protocol uses, so a
 * record maps one-to-one onto a TTYP frame (see ../docs/PROTOCOL.md):
 *   frame proto = 0x80030000 | stream   (psp2tm: stream = proto + 0x7ffd0000)
 *   stream      = PSP2TMAPILib.eConsoleOutputStream
 */

#ifndef RRC_TTY_H
#define RRC_TTY_H

#define RRC_TTY_VERSION         0x52525401u   /* "RRT" v1; rrcTtyGetInfo proves the import resolved */

#define RRC_TTY_STREAM_STDOUT   0x00          /* STREAM_STDOUT  */
#define RRC_TTY_STREAM_KERNEL0  0x90          /* STREAM_KERNEL0 */

#define RRC_TTY_SOURCE_USER     0x1000
#define RRC_TTY_SOURCE_KERNEL   0x8000

#define RRC_TTY_TEXT            108

/* 128 bytes. The tick is split so the layout is identical in every ABI. */
typedef struct RrcTtyRecord {
	unsigned char  stream;
	unsigned char  len;
	unsigned short source;
	unsigned int   pid;
	unsigned int   tid;
	unsigned int   tick_lo;          /* microseconds since boot */
	unsigned int   tick_hi;
	char           text[RRC_TTY_TEXT];
} RrcTtyRecord;

#define RRC_TTY_HANDLER_PUTCHAR 0x1
#define RRC_TTY_HANDLER_KPRINTF 0x2

typedef struct RrcTtyInfo {
	unsigned int version;
	unsigned int handlers;           /* RRC_TTY_HANDLER_* that registered */
	int          putchar_result;
	int          kprintf_result;
	unsigned int putchar_chars;      /* characters seen on the putchar sink */
	unsigned int kprintf_calls;
	unsigned int records_dropped;    /* overwritten before anyone read them */
	unsigned int records_pending;
} RrcTtyInfo;

/* Syscalls exported by rrc_tty.skprx, library RrcTty. */
int rrcTtyGetInfo(RrcTtyInfo *info);
int rrcTtyRead(RrcTtyRecord *records, int max_records);   /* returns records copied */

#endif
