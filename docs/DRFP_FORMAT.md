# DRFP / host0: file serving (DECI4 protocol 0x11000) - byte-exact format

Reverse of psp2tm.exe 3.60.0.2 (Ghidra project `TMRE`, program `psp2tm.exe`) and
PSP2Razor.dll 3.60.0.5 (project `gproj3`, program `PSP2Razor.dll`). Every claim is tagged
with the function/address it comes from. `tm!` = psp2tm.exe, `rz!` = PSP2Razor.dll.
"**Interpretation**" marks inference (mostly the on-target side, which is not in these binaries).
Live corroboration: the `%LOCALAPPDATA%\Temp\SCE\Razor\tmp_settings.ini` written by a
GPU-trace run (quoted in §4).

---

## 0. Summary

- **`host0:` file serving is DECI4 protocol `0x11000`, the message family psp2tm calls DRFP.**
  Direction: **target -> host CMD** (OPEN/READ/WRITE/CLOSE/STAT/...); **host -> target RES**. The
  target (Vita, or the plugin impersonating Razor's HUD) is the *client*; psp2tm is the *server*
  that executes the op on the PC filesystem. (`tm!FUN_140131660` routes proto `0x11000` to
  `tm!FUN_140136300`, which enqueues; the file-serving thread `tm!FUN_140100bf0` dequeues and
  dispatches in `tm!FUN_140120fe0`; responses are built with proto `0x11000` by `tm!FUN_1400db470`.)
- **`0x12000` (RDRFP) is the *reverse* direction** - host reads the *target's* filesystem, i.e. the
  CFSDClient / "map Vita as drive letter" path (`tm!FUN_140132ef0`, `CFSDClient`, `FSDDriveLetter`).
  **Not needed for the GPU trace.** The GPU trace only needs `0x11000`.
- **The whole minimum set for the GPU trace** (open-write-create-truncate, write, close; plus
  open-read, read, close, stat to read `tmp_settings.ini`) is fully specified below and is
  self-contained: no registration handshake, no "file serving enabled" flag, and - for an
  absolute `host0:C:/...` path - no dependence on `<FSRoot>`.

---

## 1. Transport framing (unchanged from PROTOCOL.md, repeated for completeness)

16-byte DECI frame header, little-endian (`tm!FUN_1400e0770` reader, `tm!FUN_1400db470` writer):

```
off size field
0   3    u24 total_len         16 <= len <= 0x11000  (whole frame incl. this header)
3   1    0x40                  marker; reader asserts == '@'
4   2    u16 flags             0
6   2    u16 node              see §2
8   4    u32 protocol          0x11000  for DRFP
12  4    u32 reserved          0
16  ...  payload
```

### DRFP payload header (8 bytes) - `tm!FUN_1400d2cb0` (decode), `tm!FUN_1400db470`+builders (encode)

```
off size field
0   4    u32 code              even = CMD (target->host), odd = RES (host->target). Full u32.
4   2    u16 msgid             request id; host ECHOES it in the matching RES.
6   2    u16 pad               0
8   ...  body
```

`tm!FUN_1400d2cb0` reads 8 payload bytes and checks `*(u32*)(frame+8) == 0x11000`; body decoders
then read `payload+8`. Builders write `CONCAT24(msgid, code)` as the 8-byte header, i.e.
`[u32 code][u16 msgid][u16 0]` (`tm!FUN_1400da0c0` etc.). The `msgid` the target puts in a CMD is
taken by the host from payload+4 and copied into the RES (e.g. `tm!FUN_140120260` passes
`*(u16*)(payload+1_dword)` = payload+4 to the RES builder).

---

## 2. Message set and code numbers - dispatcher `tm!FUN_140120fe0`

Even = CMD (target->host); RES = CMD | 1 (host->target). Names/ids confirmed against psp2tm's
embedded Event-Viewer XML (`drfp` category, file offset 0x4914d4 in psp2tm.exe: "event id is the
value of the DECI4_DRFP_CODE_XXXXXX constant") and the per-code handler in `tm!FUN_140120fe0`.

| CMD | RES | name          | CMD decoder      | RES builder        | handler          |
|-----|-----|---------------|------------------|--------------------|------------------|
| 0x00| 0x01| SETOPTIONS    | (inline)         | tm!FUN_1400daf90   | FUN_140120fe0 c0 |
| 0x02| 0x03| GETOPTIONS    | (inline)         | tm!FUN_1400da580   | FUN_140120fe0 c2 |
| 0x04| 0x05| **OPEN**      | tm!FUN_1400d2df0 | tm!FUN_1400da780   | tm!FUN_140120260 |
| 0x06| 0x07| **CLOSE**     | tm!FUN_1400d2a50 | tm!FUN_1400da0c0   | tm!FUN_14011e0e0 |
| 0x08| 0x09| **READ**      | tm!FUN_1400d2f90 | tm!FUN_1400dac20*  | tm!FUN_140121920 |
| 0x0a| 0x0b| **WRITE**     | tm!FUN_1400d37a0 | tm!FUN_1400db300   | tm!FUN_140124ee0 |
| 0x0c| 0x0d| FSTAT         | tm!FUN_1400d2c10 | tm!FUN_1400da3e0   | tm!FUN_14011f390 |
| 0x0e| 0x0f| **STAT**      | tm!FUN_1400d33d0 | tm!FUN_1400db020   | tm!FUN_1401235f0 |
| 0x10| 0x11| MKDIR         | tm!FUN_1400d2d20 | tm!FUN_1400da620   | tm!FUN_14011fc30 |
| 0x12| 0x13| RMDIR         | tm!FUN_1400d2fe0 | tm!FUN_1400dae60   | tm!FUN_140123010 |
| 0x14| 0x15| OPENDIR       | (inline c0x14)   | tm!FUN_1400da8b0   | tm!FUN_1401209c0 |
| 0x16| 0x17| CLOSEDIR      | (inline)         | tm!FUN_1400da150   | tm!FUN_14011e4e0 |
| 0x18| 0x19| READDIR       | tm!FUN_1400d2ec0 | tm!FUN_1400daab0   | tm!FUN_140122220 |
| 0x1a| 0x1b| FTRUNCATE     | (inline)         | tm!FUN_1400da4f0   | tm!FUN_14011f800 |
| 0x1c| 0x1d| TRUNCATE      | tm!FUN_1400d34a0?| tm!FUN_1400db1e0   | tm!FUN_1401242e0 |
| 0x1e| 0x1f| RENAME        | tm!FUN_1400d34a0 | tm!FUN_1400dad80   | tm!FUN_140122910 |
| 0x20| 0x21| UNLINK        | tm!FUN_1400d3600 | tm!FUN_1400db270   | tm!FUN_140124900 |
| 0x22| 0x23| SETDIRNOTIFY  | tm!FUN_1400d32b0 | tm!FUN_1400daef0   | FUN_140120fe0 c0x22 |
| 0x24| 0x25| REMOVEDIRNOTIFY| tm!FUN_1400d3030| tm!FUN_1400dacf0   | FUN_140120fe0 c0x24 |
| 0x26| 0x27| CREATE        | tm!FUN_1400d2af0 | tm!FUN_1400da1e0   | tm!FUN_14011e8e0 |
| 0x28| 0x29| FCHSTAT       | tm!FUN_1400d2bc0 | tm!FUN_1400da350   | tm!FUN_14011ef50 |
| 0x2a| 0x2b| CHSTAT        | tm!FUN_1400d2980 | tm!FUN_1400da030   | tm!FUN_14011dab0 |
| 0x2c| 0x2d| TRANSLATEPATH | tm!FUN_1400d34a0 | tm!FUN_1400db130   | tm!FUN_140123c20 |

`*` READ RES is emitted by `tm!FUN_14007c6e0`/`_c640`/`_c7a0` -> `tm!FUN_1400dac20` from the async
`ReadFileEx` completion (`tm!FUN_140117bd0` -> `tm!FUN_140116ac0`). Codes 0x40/0x41 in the dispatcher
are ACK/no-op. An unhandled/failed code is answered with **NOT_SUPPORTED (RES code 0x41)** result
`0x110c0` (`tm!FUN_1400da2d0`, default arm of `tm!FUN_140120fe0`; log string
`DECI4_RDRFP_CODE_NOT_SUPPORTED`).

### 2.1 Node id and "who may use it"

- **No registration handshake and no enable flag are required for 0x11000.** `tm!FUN_140131660`
  routes 0x11000 straight to the file-serving queue with no protocol-registration check. There is no
  `FSDFlags`/`FSDDriveLetter` gate on this path - those belong to the reverse RDRFP/CFSD path
  (`Server.xml` `<FSDFlags>49</FSDFlags>` etc.). `<FSRoot>` only affects *relative* paths (§3).
- **Node.** The host pre-registers `0x11000 -> node 0xa200` at target-object construction
  (`tm!FUN_140076680`, `MOV R15D,0xa200` @0x1400768b4, stored for the 0x11000 entry @0x140076a44 /
  0x140076b4a). The RES frame's node is looked up from that map (`tm!FUN_1400db470` ->
  `tm!FUN_1400775e0`). If the target advertises 0x11000 in NETMP `PROTO_LIST_RES`, the advertised
  node overrides it (`tm!FUN_14008db60` stores proto->node). **Recommendation for the plugin:**
  add `0x11000` to `PROTO_LIST_RES` with a non-zero node (0xa200 keeps it identical to the host
  default), and send CMD frames with that same node. The host does not validate the node on an
  incoming 0x11000 CMD, so any value is accepted, but matching 0xa200 is safest. **Interpretation:**
  advertising is prudent but, from the receive path, not strictly required - the host will process
  and answer 0x11000 CMDs even if the protocol was never listed.
- DECI header flags = 0 on both directions.

### 2.2 Result codes (sceDRFPResult, psp2tm Event XML + `tm!FUN_1400c9d20` Win32->DRFP map)

```
0        OK
0x11002  file not found          0x11005  I/O error
0x11009  bad file descriptor     0x1100c  ENOMEM
0x1100d  EACCES (no rights)      0x11010  already open
0x11011  file already exists     0x11014  ENOTDIR
0x11015  EISDIR                  0x11016  EINVAL
0x11018  too many open files     0x1101c  ENOSPC
0x1101e  read-only fs            0x11024  ENAMETOOLONG
0x11027  ENOTEMPTY               0x110c0  ENOSYS / not supported by device
0x110FF  no rights
```

---

## 3. Path encoding and how `host0:` maps to the PC

Path strings in every CMD are **UTF-8, length-prefixed *and* NUL-terminated, padded to 4 bytes**.
Decoder helper `tm!FUN_1400d39c0` reads `(len+3)&~3` bytes and asserts `buf[len-1]==0`, so the
`pathlen` field **counts the NUL**. psp2tm converts UTF-8->UTF-16 with code page **0xFDE9 = CP_UTF8**
(`tm!FUN_1401af520` inside `tm!FUN_1400ca130`).

**Absolute vs FSRoot-relative** - path builder `tm!FUN_1400ca130` + open `tm!FUN_1400cb730`:

1. UTF-8 -> UTF-16, then `/` is left as-is here; drive test is on the 3rd UTF-16 unit.
2. `tm!FUN_1400cb0f0` returns "needs root prepend" **unless** the path already has a drive
   (`path[2] == ':'`, i.e. `X:\...`) **or** is UNC (`\\?\`, `\\?\UNC`, `\\`, `//`)
   (`tm!FUN_1400cb150`/`_cb080`).
3. If it needs a root, the **FileServingRoot** string (Target1.xml `<FSRoot>`, currently
   `C:\Users\<user>\AppData\Local\SCE\PSP2TM\FSROOT\`) is prepended (`tm!FUN_1400cc150`), with a
   trailing `\` guaranteed by the root setter `tm!FUN_1400cc050`.
4. `/` are converted to `\` last (`tm!FUN_1400cd5b0` normaliser) and the result is handed to
   `CreateFileW` (`tm!FUN_1400cb730`).

Therefore:

- **`host0:C:/Users/x/tmp.pmon` opens the literal PC path `C:\Users\x\tmp.pmon`** - absolute Windows
  paths are allowed and **bypass `<FSRoot>`** because `path[2]==':'`.
- A relative `host0:foo/bar.txt` (no drive) is served as `<FSRoot>\foo\bar.txt`.
- **`host0:` itself is a target-side device prefix.** The DRFP OPEN carries the path *after*
  `host0:` (so `C:/Users/x/tmp.pmon`, not `host0:C:/...`) - otherwise `path[2]` would be `s` and the
  drive test would fail. **Interpretation** (the stripping happens in the on-target host0: device
  driver, which is not in these binaries; but it is the only reading consistent with
  `tm!FUN_1400cb0f0`, and with the fact that Razor writes an absolute drive path - see below).

### 3.1 What Razor writes (the exact `trace_filename`)

`rz!FUN_10259030` builds the two host files and the served path:

- **Host temp dir** = `GetTempPathW()` + `SCE\Razor\` (`rz!FUN_10185dd0`, slot +0x18 of the app
  object `rz!FUN_10185b90` vtable `0x1051c53c[6]`; error rt 33114 "Unable to get temporary file
  directory", rt 242 "Failed to create Razor's temp folder"). On this machine that resolves to
  `C:\Users\<user>\AppData\Local\Temp\SCE\Razor\` (8.3 short form, as GetTempPath returns it).
- It writes `tmp_settings.ini` (`CreateFileW GENERIC_WRITE, share=1, OPEN_ALWAYS`) with UTF-8 lines
  (`0x105820ac`+), `%d`/`%s` from `CCaptureOptions+4/+8/+0xc`:
  ```
  trace=1
  trace_metrics_group=%d
  trace_size=%s          (0->low 1->medium 2->high, rz!FUN_102594b0)
  trace_rate=%s
  trace_filename_count_len=0
  trace_filename=host0:<served tmp.pmon path, '\'->'/'>
  ```
  The last line is written by concatenating the literal `trace_filename_count_len=0\ntrace_filename=host0:`
  then the full temp path with `\`->`/` (`Ordinal_12633(0x5c,0x2f)` = replace `\`(0x5c) with `/`(0x2f)),
  UTF-8 via CP_UTF8 (`rz!FUN_102d8850`). **No trailing newline** after the filename.
- It converts the same temp `tmp.pmon` path to the served string and stores it at **session+0x30**
  (0x104 wchars, `rz!FUN_102d8900` CP_UTF8) as `host0:<...>/tmp.pmon`; this is the value later handed
  to the target HUD (see §3.2). `DeleteFileW` pre-cleans the output `tmp.pmon`.

`rz!FUN_102d8850`/`_102d8900` are thin `WideCharToMultiByte(CP_UTF8,...)`
wrappers (UTF-16 -> UTF-8); they do **not** touch slashes - the `\`->`/` swap is the separate
`Ordinal_12633(0x5c,0x2f)` calls. So the produced `trace_filename` string is exactly
`host0:` + `<TempPath with forward slashes>tmp.pmon`.

**Live proof** - `%LOCALAPPDATA%\Temp\SCE\Razor\tmp_settings.ini`, 169 bytes, written by a
GPU-trace run:
```
trace=1
trace_metrics_group=0
trace_size=medium
trace_rate=medium
trace_filename_count_len=0
trace_filename=host0:C:/Users/<user>/AppData/Local/Temp/SCE/Razor/tmp.pmon
```
(No terminating newline; forward slashes; 8.3 short form of the user name.)

### 3.2 How the served path reaches the target HUD (context, not DRFP)

`rz!FUN_10258c30` (DoCaptureInternal) calls `rz!FUN_10259030` (writes the files),
then passes **session+0x30** (the `host0:...tmp_settings.ini` path - actually the settings file path;
the writer stores `...tmp.pmon` at +0x30 and `...tmp_settings.ini` handling is analogous) to the HUD via
`rz!FUN_100f2720` -> `CPSP2Target` vtable **+0xfc** (`rz!FUN_101b17e0` -> `rz!FUN_101b1200`), which
DBGP-WRMEMs a 0x204-byte command (`buf[0]=1` arm/start, plus up to a 0x1ff-char string arg, format
`%s`) into the HUD's command buffer (`rz!FUN_101b1c50`). The HUD then does the
`host0:` file I/O that becomes DRFP 0x11000 traffic. (This DBGP+breakpoint dance is the subject of
`GPU_TRACE_SESSION.md`; it is not DRFP and is only summarised here so the `trace_filename` origin is
traceable end-to-end.)

---

## 4. Byte-exact CMD/RES layouts

Sizes are body bytes *after* the 8-byte DRFP payload header `[u32 code][u16 msgid][u16 0]`.
"pathlen" always includes the NUL and the field is padded to a 4-byte multiple.

### OPEN - CMD 0x04 / RES 0x05
CMD body (`tm!FUN_1400d2df0` decode; `tm!FUN_140120260` handler -> `tm!FUN_1400cb730`):
```
+0x00 u32 flags        access+disposition bits (see below)
+0x04 u32 mode         Unix-ish perm; only bit7 (W,0x80) is consulted
+0x08 u32 pathlen      strlen(path)+1
+0x0c u8  path[pad4(pathlen)]   UTF-8, NUL-terminated
```
flags bits (`tm!FUN_1400cb730` + `tm!FUN_1400cb310`; Event XML "flags"):
```
bit0 0x001 READ        bit1 0x002 WRITE         (bits0-1: 1=GENERIC_READ 2=GENERIC_WRITE 3=RW)
bit9 0x200 CREATE      bit10 0x400 TRUNCATE     bit11 0x800 EXCL
disposition = f(flags & 0xe00):
  0x000 -> OPEN_EXISTING(3)   0x200 CREATE -> OPEN_ALWAYS(4)
  0x400 TRUNC -> TRUNCATE_EXISTING(5)           0x600 CREATE|TRUNC -> CREATE_ALWAYS(2)
  0xa00 CREATE|EXCL -> CREATE_NEW(1)            0xc00 TRUNC|EXCL -> TRUNCATE_EXISTING(5)
  0xe00 -> CREATE_NEW(1)
mode: if CREATE and (mode & 0x80)==0 the file is made read-only (FILE_ATTRIBUTE_READONLY);
      set mode=0x180 (R|W) for a normal writable file. FILE_FLAG_OVERLAPPED (0x40000000) is
      always set. share mode = FILE_SHARE_READ|WRITE (3).
```
**"open for write, create+truncate"** => `flags = WRITE|CREATE|TRUNCATE = 0x002|0x200|0x400 = 0x602`
(=> GENERIC_WRITE + CREATE_ALWAYS), `mode = 0x180`.

RES 0x05 body (`tm!FUN_1400da780`):
```
success (result==0):  +0x00 u32 result=0
                      +0x04 u32 handle          (the fd for subsequent READ/WRITE/CLOSE)
                      +0x08     DeciStat[0x30]   (§4.1)          -> body = 0x38
failure:              +0x00 u32 result          (0x110xx error)
                      +0x04 u32 handle=0xffffffff                -> body = 0x08
```

### READ - CMD 0x08 / RES 0x09
CMD body (`tm!FUN_1400d2f90` reads 0x14; `tm!FUN_140121920`):
```
+0x00 u32 fd
+0x04 u32 reserved(0)
+0x08 u64 offset
+0x10 u32 nbytes        host caps a single read at 0x10000 (tm!FUN_140121920 @0x140116f58)
```
RES 0x09 body (`tm!FUN_1400dac20` + data, patched by `tm!FUN_1400da950`; emitters
`tm!FUN_14007c6e0` data / `_c7a0` EOF / `_c640` error). Fields in wire order:
```
+0x00 u32 result        0 ok; 0x11005 I/O error; 0x1100d EACCES; 0x11016 EINVAL; etc.
+0x04 u32 status        low byte = (more!=1); 0 for a normal single/last chunk
+0x08 u16 s1            =1  (internal status, constant)
+0x0a u16 s2            =1
+0x0c u32 bytesread
+0x10 u8  data[bytesread]
```
**Interpretation:** the `+0x04/+0x08/+0x0a` triple are the host's internal "1,1" markers; to parse a
read all you need is `result` (+0x00), `bytesread` (+0x0c) and `data` (+0x10). Large reads arrive as
one RES per <=0x10000 chunk (host loops `ReadFileEx`); EOF is a chunk with `bytesread==0`.
Byte offsets of the preamble are from `tm!FUN_1400dac20` disasm - verify against a
live capture before relying on the exact `+0x04..+0x0b` bytes.

### WRITE - CMD 0x0a / RES 0x0b
CMD body (`tm!FUN_1400d37a0` reads 0x14 then data; `tm!FUN_140124ee0`):
```
+0x00 u32 fd
+0x04 u32 flags         0 = normal write+reply. bit1 0x2 = no RES (fire-and-forget);
                        bit2 0x4 = reset error/byte-counter before writing (seek-to-0 semantics)
+0x08 u64 offset
+0x10 u32 nbytes
+0x14 u8  data[nbytes]  (field padded to 4 in the frame)
```
RES 0x0b body (`tm!FUN_1400db300`; emitter `tm!FUN_14007cdb0`):
```
+0x00 u32 result
+0x04 u32 byteswritten          -> body = 0x08
```

### CLOSE - CMD 0x06 / RES 0x07
CMD body (`tm!FUN_1400d2a50` reads 4):  `+0x00 u32 fd`
RES 0x07 body (`tm!FUN_1400da0c0`):     `+0x00 u32 result`   (body = 4)

### STAT - CMD 0x0e / RES 0x0f ;  FSTAT - CMD 0x0c / RES 0x0d
STAT CMD body (`tm!FUN_1400d33d0`): `+0x00 u32 pathlen` `+0x04 u8 path[pad4]`
FSTAT CMD body (`tm!FUN_1400d2c10` reads 4): `+0x00 u32 fd`
RES 0x0f / 0x0d body (`tm!FUN_1400db020` / `tm!FUN_1400da3e0`):
```
success:  +0x00 u32 result=0    +0x04 DeciStat[0x30]     -> body = 0x34
failure:  +0x00 u32 result                                -> body = 0x04
```
(Use STAT/FSTAT to learn `tmp_settings.ini`'s size before reading it, or just read until
`bytesread==0`.)

### CREATE - CMD 0x26 / RES 0x27  (create file, no fd returned)
CMD body (`tm!FUN_1400d2af0`): `+0x00 u32 ?` `+0x04 u32 mode` `+0x08 u32 pathlen` `+0x0c path`.
RES (`tm!FUN_1400da1e0`): `+0x00 u32 result` then 0x30 stat (0x38 total). Not needed for the trace -
OPEN with CREATE|TRUNCATE (flags 0x602) is the one-shot the HUD uses.

### 4.1 DeciStat (0x30) - `tm!FUN_1400cb4c0` from `GetFileInformationByHandle`
```
+0x00 u32 mode         (readonly?0x140:0x1c0) | (dir?0x4000:0x8000)   [S_IFREG=0x8000, S_IFDIR=0x4000]
+0x04 u32 deviceinfo   = dwVolumeSerialNumber
+0x08 u64 nodeinfo     = (nFileIndexHigh<<32)|nFileIndexLow
+0x10 u64 size         = (nFileSizeHigh<<32)|nFileSizeLow
+0x18 u64 atime        FILETIME/10 + 0xB36168B6A58000   (SCE epoch microseconds)
+0x20 u64 mtime        ftLastWriteTime, same transform
+0x28 u64 ctime        ftCreationTime,  same transform
```

---

## 5. Worked hex example - write `host0:C:/Users/x/tmp.pmon` (16 bytes)

Node 0xa200, all little-endian. Path sent in OPEN is the post-`host0:` string
`C:/Users/x/tmp.pmon` (19 chars + NUL = 20 bytes, pathlen 0x14, already 4-aligned). fd from OPEN_RES
assumed `0x00000003`.

### (a) target -> host  OPEN_CMD  (msgid 1, flags 0x602, mode 0x180)
frame_len = 16 + (8 + 4+4+4 + 20) = 16 + 40 = 0x38.
```
38 00 00 40  00 00  00 a2  00 10 00 00  00 00 00 00     ; DECI hdr: len=0x38, node=0xa200, proto=0x11000
04 00 00 00  01 00  00 00                               ; payload hdr: code=OPEN(4), msgid=1, pad
02 06 00 00                                             ; flags = 0x602 (WRITE|CREATE|TRUNCATE)
80 01 00 00                                             ; mode  = 0x180 (R|W)
14 00 00 00                                             ; pathlen = 0x14 (incl NUL)
43 3a 2f 55 73 65 72 73 2f 78 2f 74 6d 70 2e 70 6d 6f 6e 00   ; "C:/Users/x/tmp.pmon\0"
```
### host -> target  OPEN_RES  (echo msgid 1, result 0, handle 3, then 0x30 stat)
frame_len = 16 + (8 + 4 + 4 + 0x30) = 16 + 0x40 = 0x50.
```
50 00 00 40  00 00  00 a2  00 10 00 00  00 00 00 00     ; DECI hdr
05 00 00 00  01 00  00 00                               ; code=OPEN_RES(5), msgid=1
00 00 00 00                                             ; result = 0
03 00 00 00                                             ; handle = 3
00 80 00 00  <serial:4>  <nodeinfo:8>  10 00 00 00 00 00 00 00   ; DeciStat: mode=0x8000, dev, node, size=0x10 (post-first-write it reflects file)
<atime:8> <mtime:8> <ctime:8>                          ; (stat bytes 0x18..0x2f)
```
(The stat mirrors the freshly created file; `mode` low = 0x8000 file bit, high nibble 0x140/0x1c0
depending on read-only. Only `result` and `handle` are load-bearing for the client.)

### (b) target -> host  WRITE_CMD  (msgid 2, fd 3, flags 0, offset 0, 16 bytes)
frame_len = 16 + (8 + 4+4+8+4 + 16) = 16 + 44 = 0x3c.
```
3c 00 00 40  00 00  00 a2  00 10 00 00  00 00 00 00     ; DECI hdr, len=0x3c
0a 00 00 00  02 00  00 00                               ; code=WRITE(0x0a), msgid=2
03 00 00 00                                             ; fd = 3
00 00 00 00                                             ; flags = 0
00 00 00 00 00 00 00 00                                 ; offset = 0
10 00 00 00                                             ; nbytes = 16
<16 bytes of file data>                                 ; e.g. "PMON" header start...
```
### host -> target  WRITE_RES  (echo msgid 2, result 0, byteswritten 16)
frame_len = 16 + (8 + 4 + 4) = 0x20.
```
20 00 00 40  00 00  00 a2  00 10 00 00  00 00 00 00     ; DECI hdr, len=0x20
0b 00 00 00  02 00  00 00                               ; code=WRITE_RES(0x0b), msgid=2
00 00 00 00                                             ; result = 0
10 00 00 00                                             ; byteswritten = 16
```
(Repeat WRITE with an increasing `offset` for a larger `.pmon`; the write is positioned by the
`offset` field via `WriteFile` on the overlapped handle - `tm!FUN_1400c8e40` sets
`Overlapped.Offset` from bytes +8..+0xf.)

### (c) target -> host  CLOSE_CMD  (msgid 3, fd 3)
frame_len = 16 + (8 + 4) = 0x1c.
```
1c 00 00 40  00 00  00 a2  00 10 00 00  00 00 00 00     ; DECI hdr, len=0x1c
06 00 00 00  03 00  00 00                               ; code=CLOSE(6), msgid=3
03 00 00 00                                             ; fd = 3
```
### host -> target  CLOSE_RES  (echo msgid 3, result 0)
frame_len = 0x1c.
```
1c 00 00 40  00 00  00 a2  00 10 00 00  00 00 00 00     ; DECI hdr
07 00 00 00  03 00  00 00                               ; code=CLOSE_RES(7), msgid=3
00 00 00 00                                             ; result = 0
```

### Reading `tmp_settings.ini` (symmetric): 
OPEN flags `0x001` (READ -> GENERIC_READ, disposition OPEN_EXISTING), mode `0x100`; then READ_CMD
(fd, offset 0, nbytes e.g. 0x1000) -> READ_RES gives `result`,`bytesread`,`data`; loop offset until
`bytesread==0`; CLOSE. Path after `host0:` = `C:/Users/<user>/AppData/Local/Temp/SCE/Razor/tmp_settings.ini`.

---

## 6. What psp2tm logs at LogLevel 2
`Server.xml` currently `<LogLevel>2</LogLevel>`; log lines are
`0x<tid>\t<uptime_s>\t<sev>\tMSG\t<CATEGORY> <text>` in
`%LOCALAPPDATA%\SCE\PSP2TM\ServiceLog.log` (category table `tm!FUN_14007a800`:
FILESERVER=2, FSD=0x800). Gating (each log site tests `LogLevel > N`):

- **The successful DRFP path is nearly silent at level 2.** OPEN's `OPEN: <path> <fd> <handle>`
  (category FILESERVER=2) is gated `LogLevel > 3` (`tm!FUN_1400cb730` @0x1400cb7..), so it needs
  **LogLevel 4** to appear. `FileServingThreadProc exiting` is also `>3`.
- **Failures are visible at level 2.** `Failed to send DRFP response for command ` and
  `Failed to send DRFP response for overlapped operation` (FILESERVER=2) are gated `LogLevel > 0`
  (`tm!FUN_140120fe0`, `tm!FUN_140121920`); `Failed to send DRFP NOT SUPPORTED error for command `
  likewise.
- The `0x11000` CMDs are **enqueued without a "Decoding ..." line** (`tm!FUN_140136300` just releases
  the semaphore), so - unlike TSMP/NETMP/RDRFP - you will **not** see `DECI Decoding DRFP ...`. The
  `Decoding RDRFP response Code:0x`/`Waiting for RDRFP response Code:0x` lines are the *reverse*
  0x12000 path (host reading the target), not this one.
- The rich per-op trace (OPEN/READ/WRITE/CLOSE with paths, fds, offsets, byte counts, result codes)
  lives in the **Event Viewer** `drfp` category (psp2tm Event XML, `event id == DECI4_DRFP_CODE_*`),
  not in ServiceLog - enable file-serving events in Neighborhood's Event Viewer to watch a live run.

**Practical check for a live run:** with LogLevel 2, expect ServiceLog to stay quiet on success;
a bug shows up as `Failed to send DRFP response for command <code>`. To confirm the OPEN path
byte-for-byte, temporarily raise `<LogLevel>` to 4 to get the `OPEN: <path> <fd> <handle>` lines,
and/or use the Event Viewer `drfp` view (fields: operation, file descriptor, requested/actual path,
mode, flags, offset, reqbytes/bytesread|written, result).

---

## 7. What the plugin needs

1. Advertise `0x11000` in NETMP `PROTO_LIST_RES` with node 0xa200 (non-zero; §2.1). Version/limit
   fields are not checked for DRFP - reuse the existing 0x03600000 / 0x10800 the plugin already
   sends for other protocols.
2. On the HUD "arm" command, the plugin (as target) issues, on proto 0x11000, node 0xa200:
   READ of `host0:.../tmp_settings.ini` (OPEN read / READ loop / CLOSE), parse `trace_filename=`,
   then OPEN(flags 0x602, mode 0x180) / WRITE(offset-positioned, <=0x10000 per frame) / CLOSE of the
   `tmp.pmon` path (its `host0:`-stripped absolute form). `.pmon` bytes come from `pmon_trace.c`.
3. No file-serving enable, no FSRoot dependency (absolute path), no RDRFP (0x12000) needed.
