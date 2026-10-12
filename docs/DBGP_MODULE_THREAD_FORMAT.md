# DECI4 DBGP MODULE (0x40) and THREAD (0x30) response wire formats (psp2tm.exe)

This is the companion to `DBGP_PROCINFO_FORMAT.md` and uses the same conventions: all values are
little-endian, and every offset is relative to the **DBGP payload** (DECI4 frame + 0x10) unless it
says ENTRY+. Each width is backed by the psp2tm function that reads it.

Builders plus a self-test that mirrors these decoders: `tools/dbgp_builders.py`
(run `python tools/dbgp_builders.py`).

---

## 0. Summary: what Razor sent, and what it will ask for next

| Request payload | Name | RES code | Transaction | Req builder | Validator | Handler | List builder | Entry decoder |
|---|---|---|---|---|---|---|---|---|
| `00 40 00 00 \| pid` | **MODULE GET_MOD_INFO** (Razor's request) | `0x01` | `FUN_140084760` | `FUN_1400d8ac0` | `FUN_1400d06f0` | `FUN_14010bf40` | `FUN_1400e3740` | `FUN_1400f6570` (+ `FUN_1400e3fc0` segments) |
| `00 40 02 00 \| pid \| modid` | MODULE GET_META_DATA | `0x03` | `FUN_140084670` | `FUN_1400d8a30` | `FUN_1400d0660` | `FUN_14010c260` | n/a | n/a (raw bytes) |
| `00 40 10 00 \| pid` | MODULE GET_LIB_INFO | `0x11` | `FUN_1400845a0` | `FUN_1400d89b0` | `FUN_1400d05b0` | `FUN_14010b370` | `FUN_1400e3490` | `FUN_1400f5e60` (+ `FUN_14010b680` name) |
| `00 30 02 00 \| pid` | **THREAD GET_THREAD_INFO_EX** (thread list, sent FIRST) | `0x03` | `FUN_1400850d0` | `FUN_1400d9140` | `FUN_1400d0da0` | `FUN_140112230` | `FUN_1400e48a0` | `FUN_1400f6e90` |
| `00 30 00 00 \| pid` | THREAD GET_THREAD_INFO (fallback) | `0x01` | `FUN_140085000` | `FUN_1400d90c0` | `FUN_1400d0e40` | `FUN_140112230` | `FUN_1400e49d0` | `FUN_1400f7020` |
| `00 30 14 00 \| pid` | THREAD GET_THREAD_NAMES | `0x15` | `FUN_1400851a0` | `FUN_1400d91c0` | `FUN_1400d0ee0` | `FUN_140111f50` | inline | inline |

Names come from the RES name tables: `FUN_1400d1810` for MODULE (`0x01 GET_MOD_INFO_RES`,
`0x03 GET_META_DATA_RES`, `0x11 GET_LIB_INFO_RES`) and `FUN_140078cc0` for THREAD (`0x01
GET_THREAD_INFO_RES`, `0x03 GET_THREAD_INFO_EX_RES`, `0x11 SUSPEND`, `0x13 RESUME`, `0x15
GET_THREAD_NAMES`, `0x17 GET_STACK_INFO`, `0x21 GET_SYNC_INFO`, `0x31 GET_APP_OBJECT_INFO`, `0x33
GET_FIBER_STACK_INFO`). Each CMD code is its RES code minus 1.

**Razor's request** `00 40 00 00 45 00 01 40` is `DBGP_MODULE_GET_MOD_INFO_CMD` for pid `0x40010045`.
The request builder `FUN_1400d8ac0` writes u32 `0x4000` (bytes `00 40 00 00`) and then u32 pid.

**The thread list comes next.** The only caller that builds a ThreadInfo list is `FUN_140112230`.
It sends **GET_THREAD_INFO_EX first** (`FUN_1400850d0`). It falls back to plain GET_THREAD_INFO
(`FUN_140085000`) **only when the EX transaction returns exactly `8`**, meaning the target put
`result = 8` in the EX response (see section 1). Any other error is reported as-is.

### Request payload format (all DBGP CMDs)

The request builders (`FUN_1400d8ac0`, `FUN_1400d9140`, and the others) call `FUN_1400db470(pkt,
0x20000, 0)` and then append:
```
+0x00 u32  b0 | group<<8 | code<<16      (b0 = 0x00)
+0x04 ...  arguments (u32 pid; GET_META_DATA adds u32 module_id at +0x08)
```
Requests have **no** seq/frag/result words. Those exist only in responses.

---

## 1. Common response header and transaction rules (`FUN_14008f540`, `FUN_1400d1c80`)

```
+0x00 u8   b0          not checked (echo the request's byte 0)
+0x01 u8   group       must equal the request group   (predicate FUN_140093de0: payload+1)
+0x02 u8   code        must equal the RES code         (predicate FUN_140093de0: payload+2)
+0x03 u8   0
+0x04 u16  seq         first frame: MUST be 0          (else internal 0x100018 -> SCE 0x80040293)
+0x06 u8   frag flags  bit0 = more fragments follow
+0x07 u8   0           (not read)
+0x08 u32  result      0 = OK. Nonzero is returned as-is (see below)
+0x0c ...  body (message specific)
```

The disassembly of `FUN_14008f540` (0x14008f984 through 0x14008fad7) proves these rules:

* `FUN_140091a10` receives DBGP packets until the predicate `FUN_140093de0` matches, meaning
  `payload[1] == group && payload[2] == RES code`. Packets that don't match are dispatched elsewhere
  (`FUN_140081000`). The deadline is `_Xtime_get_ticks() + 50000000` (5 s) for every message here.
  On timeout the transport returns `0x180000`, which is changed to `0x180001` (SCE `0x80041003`).
* `payload+8 != 0`: the transaction returns `FUN_140074990(result)`, which is the identity function.
  The handlers map it through `FUN_1401417a0`, so for example `8` becomes `0x80040223`. **No validator
  runs**, so an error response can be only the 12-byte header (`error_res()`).
* `payload+4 (u16) != 0` on the first frame gives `0x100018`.
* **Fragmentation.** If `payload+6 & 1`, the transaction keeps receiving frames that match the same
  group/code under the same deadline. Each continuation frame must have `result == 0` (else
  `0x100019` -> `0x80040294`) and `seq == previous + 1`, so seq runs `1, 2, 3, ...` (else
  `0x100018`). The transaction then appends `frame[0x1c : u24 total_len]` to the first frame's
  buffer (`FUN_140242bd0(buf, payload+0x0c, total_len - 0x1c)`). In other words, each continuation
  repeats the 12-byte header, and only the bytes after it are appended raw. **The split can fall
  anywhere, even inside an entry.** The loop stops on the first frame whose bit0 is clear.
* The validators then run on the reassembled buffer. Their bounds checks (`FUN_140242a90`) compare
  against the real accumulated byte count, not the first frame's u24 length.
* Frame size: no decoder enforces a limit. psp2tm's own send side limits a packet to `< 0x10fed`
  bytes, and receive buffers are reserved at `0x11000`. Frames of <= 0x10000 bytes are a safe choice.
  `fragment(payload, max_frame)` in the builders implements the rules above.
* Validation failure makes the transaction return `0x100007` (SCE `0x80040282`). An echoed pid that
  doesn't match gives `0x100010` (SCE `0x8004028b`). A GET_META_DATA module id that doesn't match
  gives `0x100014` (SCE `0x8004028f`).

`FUN_1400cdeb0` is the entry walker for self-sized entries. For each of `count` entries it checks
that `*entry` bytes are in bounds, then does `entry += *entry`. The list builders
(`FUN_1400e3740`, `FUN_1400e48a0`, `FUN_1400e49d0`, `FUN_1400e3490`) advance the same way
(`param_2 += *param_2`). **Every entry's first u32 is therefore its own total size**, and entries are
packed back to back.

---

## 2. MODULE GET_MOD_INFO_RES (group 0x40, code 0x01)

### 2a. Body: validator `FUN_1400d06f0`, transaction `FUN_140084760`, handler `FUN_14010bf40`

```
+0x00 00 40 01 00 | +0x04 seq=0,frag,0 | +0x08 u32 result = 0
+0x0c u32 pid          FUN_1400d06f0 requires 8 bytes at +0x0c. FUN_140084760: *p != pid -> 0x100010
+0x10 u32 count        number of modules (0 is valid: empty ModuleInfoList)
+0x14 entry[0..count-1]  self-sized. FUN_1400cdeb0(pkt, p+0x14, count) must succeed, and when
                          count != 0, entry[0].size > 0x4f (i.e. >= 0x50)
```
The validator returns `p+0x0c`. `FUN_14010bf40` then calls
`FUN_1400e3740(&vec, ret+8 /*=p+0x14*/, *(ret+4) /*=count*/)`, which builds a `vector<ModuleInfo>`
of 0x78-byte elements and stores it at object+0x38 (`FUN_1400f3660`).

### 2b. Module entry: decoder `FUN_1400f6570` (confirmed by disassembly), names from formatter `FUN_1401ef7e0`

```
ENTRY+0x00 u32  entry_size      >= 0x50. Recommended: 0x50 + nseg*0x14 + 0x10
ENTRY+0x04 u32  ID              module UID           -> [0]    "ID:"
ENTRY+0x08 u32  SdkVersion                           -> [2]    "SdkVersion:"
ENTRY+0x0c u16  ModuleVersion   MOVZX word [+0xc]    -> [3]    "ModuleVersion:"
ENTRY+0x0e u16  (not read)
ENTRY+0x10 u8   Type            MOVZX byte [+0x10]   -> [4]    "Type:"  (eModuleTypes: 0x10 FIXED_ELF, 0x20 PRX)
ENTRY+0x11 u8   (not read)
ENTRY+0x12 u16  Flags           MOVZX word [+0x12]   -> [5]    "Flags:"
ENTRY+0x14 u32  StartEntryAddress                    -> [6]
ENTRY+0x18 u32  ReferenceCount                       -> [7]
ENTRY+0x1c u32  StopEntryAddress                     -> [8]
ENTRY+0x20 u32  ExitEntryAddress                     -> [9]
ENTRY+0x24 char[32] ModuleName  FUN_140143460(src=+0x24, dst, 0x1a): std::string::assign(src, 26)
                                (FUN_140010fb0), cut at first NUL, then UTF-8 -> wide. At most 26
                                bytes are read. The slot is 32 bytes because Status is read from
                                the fixed offset +0x44. NUL-pad it.                     -> [10] "ModuleName:"
ENTRY+0x44 u32  Status          eModuleStatus 0 LOADED,1 STARTING,2 LIVE,3 STOPPING,4 STOPPED -> [0x12]
ENTRY+0x48 u32  GUID            (IModule.Fingerprint)                         -> [1]  "GUID:"
ENTRY+0x4c u32  SegmentCount n  FUN_1400e3fc0(&vec, entry+0x50, n)
ENTRY+0x50 seg[0..n-1], each 0x14 bytes (FUN_1400e3fc0 reads seg+4..seg+0x13, stride 5 words):
     +0x00 u32  (not read; the builder writes 0x14, like SceKernelSegmentInfo.size)
     +0x04 u32  Attributes   -> seg[0] "Attributes:"   (formatter FUN_1401eff50)
     +0x08 u32  BaseAddress  -> seg[1] "BaseAddress:"
     +0x0c u32  Size         -> seg[2] "Size:"
     +0x10 u32  Alignment    -> seg[3] "Alignment:"
ENTRY+0x50+n*0x14  tail, read only if (n+4)*0x14 < entry_size (disasm 0x1400f668a..0x1400f66a3):
     +0x00 u32  StartOfExidx -> [0x1a]
     +0x04 u32  EndOfExidx   -> [0x1b]
     +0x08 u32  StartOfExtab -> [0x1c]
     +0x0c u32  EndOfExtab   -> [0x1d]      (otherwise all four are 0)
```
Checks: only `entry[0].size >= 0x50` and the size-based bounds walk. The module format has no path
string.

---

## 3. MODULE GET_LIB_INFO_RES (0x40/0x11) and GET_META_DATA_RES (0x40/0x03)

### 3a. GET_LIB_INFO_RES: validator `FUN_1400d05b0`, decoder `FUN_1400f5e60`, formatter `FUN_1401ef440`
```
+0x0c u32 pid (checked -> 0x100010) | +0x10 u32 count | +0x14 entries (self-sized)
validator: 8 bytes at +0x0c; if count != 0, entry[0].size > 0x23; then FUN_1400cdeb0 walk.
ENTRY+0x00 u32 entry_size
ENTRY+0x04 u32 LibraryID       -> [0]
ENTRY+0x08 u32 ModuleID        -> [1]
ENTRY+0x0c u32 Attributes      -> [2]
ENTRY+0x10 u32 ReferenceCount  -> [3]
ENTRY+0x14 u32 A = #exported functions
ENTRY+0x18 u32 B = #exported variables
ENTRY+0x1c u32 C = #TLS offsets
ENTRY+0x20 u32 D = #client module ids
ENTRY+0x24 A x {u32 NID -> ExportedFnNIDs[0x18], u32 addr -> ExportedFnAddresses[0x0c]}
           B x {u32 NID -> ExportedVarNIDs[0x1e], u32 addr -> ExportedVarAddresses[0x12]}
           C x u32 -> TLSOffsetList[0x24]
           D x u32 -> ClientModuleIDList[0x2a]
ENTRY+0x24+(2A+2B+C+D)*4: u32 name_len (FUN_14010b680: if nonzero, name follows at +4)
           char[] Name, NUL-terminated UTF-8, pad to 4                   -> [4] "Name:"
```

### 3b. GET_META_DATA_RES: validator `FUN_1400d0660`, transaction `FUN_140084670`
Request `00 40 02 00 | u32 pid | u32 module_id`. The builder `FUN_1400d8a30` writes
`CONCAT44(modid, pid)`, which puts pid first.
```
+0x0c u32 pid        FUN_140084670: != request pid   -> 0x100010
+0x10 u32 module_id  FUN_140084670: != request modid -> 0x100014
+0x14 u32 len
+0x18 u8[len] data, padded to 4. Validator: 12 bytes at +0x0c, then pad4(len)+12 bytes at +0x0c
```
`FUN_14007ae40(obj+0x38, p+0x18, len, 0)` stores the pointer and length as the IModule.MetaData blob.

---

## 4. THREAD GET_THREAD_INFO_EX_RES (0x30/0x03) and GET_THREAD_INFO_RES (0x30/0x01)

### 4a. Body: validators `FUN_1400d0da0` (EX) and `FUN_1400d0e40` (basic) are identical apart from code
```
+0x00 00 30 03 00 (EX) or 00 30 01 00 (basic) | +0x04 seq=0 | +0x08 result = 0
+0x0c u32 pid     8 bytes at +0x0c required. FUN_1400850d0 / FUN_140085000: != pid -> 0x100010
+0x10 u32 count
+0x14 entries     FUN_1400cdeb0 walk only. There is NO minimum-size check, but the decoders read
                  fixed offsets up to +0xac (basic) or +0xd0 (EX), so use those sizes
```
`FUN_140112230`: `FUN_1400e48a0(&vec, entries, *(ret+4))` for EX or `FUN_1400e49d0(...)` for basic.
Both build `vector<ThreadInfo>` with 0xd0-byte elements and store it at object+0x38.
**Fallback:** if the EX transaction returns `8` (the target sent `result = 8`), the handler sends
GET_THREAD_INFO instead.

### 4b. Thread entry: decoders `FUN_1400f7020` (basic) and `FUN_1400f6e90` (EX), names from formatter `FUN_1401f2e20`

Both decoders read identical offsets for 0x00..0xab. EX adds WaitDetails.
```
ENTRY+0x00 u32  entry_size          basic: 0xAC   EX: 0xD0
ENTRY+0x04 u32  ThreadID                                   -> [0]    "ThreadID:"
ENTRY+0x08 char[32] Name            FUN_1401af520(+8, len=-1, CP_UTF8): unbounded NUL-terminated read.
                                    The next field is hard-coded at +0x28, so it MUST be NUL-terminated
                                    inside the slot (max 31 bytes)   -> [2]  "szThreadName:"
ENTRY+0x28 u32  InitAttributes                             -> [0x0a]
ENTRY+0x2c u32  CurrentAttributes                          -> [0x0b]
ENTRY+0x30 u32  Status   (eThreadStatus 1 RUNNING,2 READY,4 STANDBY,8 WAITING,0x10 DORMANT,...) -> [0x0c]
ENTRY+0x34 u32  EntryAddress                               -> [0x0d]
ENTRY+0x38 u32  StackAddressTop                            -> [0x0e]
ENTRY+0x3c u32  StackSize                                  -> [0x0f]
ENTRY+0x40 u32  (not read by either decoder)
ENTRY+0x44 u32  ArgSize                                    -> [0x10]
ENTRY+0x48 u32  ArgBlockBaseAddress                        -> [0x11]
ENTRY+0x4c u32  InitialPriority                            -> [0x12]
ENTRY+0x50 u32  CurrentPriority                            -> [0x13]
ENTRY+0x54 u32  InitialCPUAffinityMask                     -> [0x14]
ENTRY+0x58 u32  CurrentCPUAffinityMask                     -> [0x15]
ENTRY+0x5c u32  LastCPUID                                  -> [0x16]
ENTRY+0x60 u32  WaitStateType                              -> [0x17]
ENTRY+0x64 u32  WaitTargetID                               -> [0x18]
ENTRY+0x68 u64  ClockRun                                   -> [0x1a] (qword)
ENTRY+0x70 u32  StopReason.size     not read. Write 0x14 (same block as the process entry, where it is validated)
ENTRY+0x74 u32  StopReason.Code                            -> [0x1c]  (FUN_1401f0790 "Code:")
ENTRY+0x78 u32  StopReason.CodeSpecificId                  -> [0x1d]
ENTRY+0x7c u32  StopReason.reserved (not read)
ENTRY+0x80 u32  StopReason.Attribute                       -> [0x1e]
ENTRY+0x84 u32  ExitStatus                                 -> [0x1f]
ENTRY+0x88 u32  InterruptPreemptCount                      -> [0x20]
ENTRY+0x8c u32  ThreadPreemptCount                         -> [0x21]
ENTRY+0x90 u32  ReleaseCount                               -> [0x22]
ENTRY+0x94 u32  ChangeCPUCount                             -> [0x23]
ENTRY+0x98 u32  VFPMode                                    -> [0x24]
ENTRY+0x9c u32  CurrentPC                                  -> [0x25]
ENTRY+0xa0 u32  WaitTimeout                                -> [0x26]
ENTRY+0xa4 u64  WaitDetail                                 -> [0x28] (qword)
--- end of basic entry (0xAC) ---
ENTRY+0xac u32[9] WaitDetails (EX only): memcpy(elem+0xa8, entry+0xac, entry_size > 0xcf ? 0x24 : 0x20)
                                                           -> [0x2a..0x32]  "WaitDetails:"
--- end of EX entry (0xD0) ---
```
Note: if an EX entry is shorter than 0xD0, the host still copies 0x20 bytes starting at +0xac.

### 4c. GET_THREAD_NAMES_RES (0x30/0x15): validator `FUN_1400d0ee0`, consumer `FUN_140111f50`
```
+0x0c u32 count          NO pid echo here, and FUN_1400851a0 checks nothing
+0x10 count x 0x24-byte records (FUN_1400ce090 bounds count*0x24):
      +0x00 u32 ThreadID
      +0x04 char[32] name, NUL-terminated UTF-8 (FUN_1401af520 len=-1). Stride is 9 words
```

---

## 5. Worked examples (generated by `tools/dbgp_builders.py`, then re-decoded by its host mirror)

### 5a. GET_MOD_INFO_RES: pid 0x40010045, one module "PCSE00000", 2 segments (payload 0x9c; frame total_len 0xac)
```
0000  00 40 01 00 00 00 00 00 00 00 00 00 45 00 01 40   hdr / seq / result=0 / pid
0010  01 00 00 00 88 00 00 00 47 00 01 40 11 00 65 03   count=1 | E+0 size=0x88 | ID | SdkVersion
0020  01 01 00 00 20 00 00 00 01 01 00 81 01 00 00 00   Ver=0x101,pad | Type=0x20,pad,Flags | Start | RefCnt
0030  00 00 00 00 00 00 00 00 50 43 53 45 30 30 30 30   Stop | Exit | Name "PCSE0000...
0040  30 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ...0" (32-byte slot)
0050  00 00 00 00 00 00 00 00 02 00 00 00 78 56 34 12   | Status=LIVE | GUID
0060  02 00 00 00 14 00 00 00 05 00 00 00 00 00 00 81   nseg=2 | seg0: 0x14, attr 5, base 0x81000000
0070  00 00 02 00 10 00 00 00 14 00 00 00 06 00 00 00         size 0x20000, align 0x10 | seg1 ...
0080  00 00 10 81 00 40 00 00 10 00 00 00 00 00 00 00         base 0x81100000, size 0x4000, align | exidx..
0090  00 00 00 00 00 00 00 00 00 00 00 00                     .. extab (tail present: 0x78 < 0x88)
```

### 5b. GET_THREAD_INFO_EX_RES: pid 0x40010045, one thread (payload 0xe4; entry 0xd0)
```
0000  00 30 03 00 00 00 00 00 00 00 00 00 45 00 01 40
0010  01 00 00 00 d0 00 00 00 49 00 01 40 50 43 53 45   count | size=0xd0 | TID | name...
0020  30 30 30 30 30 00 00 00 00 00 00 00 00 00 00 00
0030  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ...name (ends 0x3b) | E+0x28 InitAttr
0040  00 00 00 00 01 00 00 00 01 01 00 81 00 00 20 81   Attr | Status=1 | Entry | StackTop
0050  00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00   StackSize | +0x40 | ArgSize | ArgBlock
0060  00 01 00 10 00 01 00 10 00 00 00 00 00 00 00 00   InitPrio | Prio | InitAff | Aff
0070  00 00 00 00 00 00 00 00 00 00 00 00 40 e2 01 00   LastCPU | WaitType | WaitTarget | ClockRun(lo)
0080  00 00 00 00 14 00 00 00 00 00 00 00 00 00 00 00   ClockRun(hi) | StopReason size=0x14, Code, CodeId
0090  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   rsv | Attribute | ExitStatus | IntPreempt
00a0  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ThrPreempt | Release | ChangeCPU | VFP
00b0  00 02 00 81 00 00 00 00 00 00 00 00 00 00 00 00   PC=0x81000200 | WaitTimeout | WaitDetail(u64)
00c0  00 00 00 00 ... (WaitDetails 9 x u32 to 0xe4)
```
The basic GET_THREAD_INFO_RES is the same with code `0x01` and entry size `0xac`, which drops the
last 0x24 bytes.

---

## 6. Using the builders

```python
from dbgp_builders import build_reply, module_list_res, thread_info_ex_res, fragment
# inside the mock's DBGP handler, with pay = request payload:
res = build_reply(pay, modules_by_pid={pid: [dict(id=..., name="eboot", segments=[...])]},
                  threads_by_pid={pid: [dict(id=..., name="main", status=1, pc=...)]})
if res is not None:
    for part in fragment(res):            # one element unless > 0x10000 bytes
        send(frame(part, node, DBGP, flags))
```
`module_list_res(b0, group, code, seq_bytes, modules, pid)` and the other builders accept either the
request code or the RES code; they write `code | 1`. Leave `seq_bytes` as `None` (zeros), because a
nonzero seq on the first frame is rejected. `build_reply(..., thread_ex=False)` answers EX with
`result = 8`, which exercises the GET_THREAD_INFO fallback.

---
---

# Part B: PROCESS group (0x20), SYSTEM memory (0x10), SYSTEM notifications

Sections 7-11 use the same conventions and the same common header/transaction rules as section 1.
Builders are in `tools/dbgp_builders.py`, and `build_reply()` now handles groups 0x20 and 0x10.

## 7. Message table

The RES names come from `FUN_1400782e0` for PROCESS and `FUN_140078590` for SYSTEM.
Every transaction below uses a 5 s deadline.

| Request payload | Name | RES | Transaction | Req builder | Validator | TMAPI handler | TMAPI method |
|---|---|---|---|---|---|---|---|
| `00 20 00 00` | GET_PROCESS_INFO | 0x01 | `FUN_140084bf0` | `FUN_1400d8db0` | `FUN_1400d0a20` | `FUN_14010dcc0` | ProcessInfo list (see DBGP_PROCINFO_FORMAT.md) |
| `00 20 10 00 \| pid \| flags` | **ATTACH_PROCESS** (Razor's current request) | 0x11 | `FUN_140083b10` | `FUN_1400d82b0` | `FUN_1400cfe50` | `FUN_1400f9090` | `IProcess.Attach(nFlags)` |
| `00 20 12 00 \| pid \| resume_flag` | DETACH_PROCESS | 0x13 | `FUN_140084000` | `FUN_1400d8610` | `FUN_1400d01c0` | `FUN_1400ff5f0` | `Detach(nResumeFlag)` |
| `00 20 20 00 \| pid` | SUSPEND_PROCESS | 0x21 | `FUN_140085b60` | `FUN_1400d9a50` | `FUN_1400d21f0` | `FUN_140140270` | `Suspend(out IStopNotification, out FailedThreads)` |
| `00 20 22 00 \| pid \| n \| nxtid` | RESUME_PROCESS | 0x23 | `FUN_140085530` | `FUN_1400d9430` | `FUN_1400d1e10` | `FUN_14013af90` | `Resume(pThreadIds)` returns a u32 array |
| `00 20 24 00 \| pid` | SUSPEND_APPLICATION | 0x25 | `FUN_140083a40` | `FUN_1400d8230` | `FUN_1400cfdf0` | `FUN_1400f8e50` | `ApplicationSuspend()` |
| `00 20 26 00 \| pid` | RESUME_APPLICATION | 0x27 | `FUN_140083970` | `FUN_1400d81b0` | `FUN_1400cfd90` | `FUN_1400f8c10` | `ApplicationResume()` |
| `00 20 30 00 \| pid \| size` | ALLOC_EXEC_PAGE | 0x31 | `FUN_1400838a0` | `FUN_1400d8120` | `FUN_1400cfc70` | `FUN_1400f8490` | `AllocateExecutableMemoryPage(size)` returns addr |
| `00 20 32 00 \| pid \| size` | ALLOC_DATA_PAGE | 0x33 | `FUN_1400837d0` | `FUN_1400d8090` | `FUN_1400cfc10` | `FUN_1400f8230` | `AllocateDataMemoryPage(size)` returns addr |
| `00 20 40 00 \| pid` | GET_MEMBLK_INFO | 0x41 | `FUN_140085260` | `FUN_1400d9240` | `FUN_1400d0f80` | `FUN_14010bc10` | `IProcess.MemoryBlocks` |
| `00 10 00 00` | SYSTEM GET_CONF | 0x01 | `FUN_140084190` | `FUN_1400d8720` | `FUN_1400d02a0` | `FUN_140109170` | |
| `00 10 10 00 \| pid \| addr \| size` | **SYSTEM RDMEM** | 0x11 | `FUN_140085330` | `FUN_1400d92c0` | `FUN_1400d1580` | `FUN_14010b790` | `GetMemory(addr, count)` |
| `00 10 12 00 \| pid \| addr \| len \| data` | **SYSTEM WRMEM** | 0x13 | `FUN_140085ed0` | `FUN_1400d9db0` | `FUN_1400d2520` | `FUN_14013db60` | `SetMemory(addr, buffer)` |

The PROCESS group has **no KILL or EXIT code**. `IProcess.Kill`/`Exit` do not use DBGP group 0x20
(`FUN_1400782e0` only lists 0x01..0x41 above). Other SYSTEM codes exist but are not covered here:
GET_REG/SET_REG (0x05/0x07), BATCH (0x21), and HW/SW watchpoints and breakpoints (0x31..0x4d).

Argument order is proven by the request builders. `CONCAT44(arg2, arg1)` puts arg1 in the low four
bytes, so the pid always comes first. Razor's `00 20 10 00 45 00 01 40 00 00 00 00` is therefore
ATTACH pid=0x40010045 flags=0, matching the TM log line "ATTACH_PROCESS { ProcessID:1073807429
Flags:0 }".

### 7a. Is a header-only error reply (nonzero result) tolerated?

**Yes, for every code.** `FUN_14008f540` returns the nonzero `result` before any validator runs
(section 1). The handler maps it through `FUN_1401417a0` and reports it to the TMAPI caller as an SCE
error; nothing times out. Unknown small codes map to `0x800402ec`, and codes outside the table map
to `0x8004021b`. Some results get special handling:

| Code | Result | psp2tm behaviour |
|---|---|---|
| ATTACH 0x10 | `0x20052` | Treated as **success** (`FUN_1400f9090`: `iVar3 != 0x20052 && iVar3 != 0` is the error test). Likely "already attached" |
| SUSPEND_PROCESS 0x20 | `0x20058` | Retried once after a short wait, then reported as an error |
| SUSPEND_PROCESS 0x20 | `0x20056` | Treated as **success** with a flag set ("already stopped") and no StopNotification data |
| THREAD GET_THREAD_INFO_EX 0x02 | `8` | Falls back to GET_THREAD_INFO (section 4) |
| RDMEM, chunked (> 0x10000) | any | The first failing chunk aborts the whole GetMemory call |

---

## 8. PROCESS responses (after the 12-byte header)

### 8a. ATTACH_PROCESS_RES (0x20/0x11): the 12-byte header alone
Validator `FUN_1400cfe50`: group `' '`=0x20, code 0x11. If `result == 0` it bounds-checks **0 bytes**
at +0x0c. If `result == 0x20052` it accepts with no check. There is **no pid echo and no body**.
```
00 20 11 00  00 00 00 00  00 00 00 00        (payload 12 bytes, frame total_len 0x1c)
```
The handler `FUN_1400f9090` replies to the client immediately. **psp2tm does not wait for any
notification after attach.** The earlier 0x80041003 was simply the 5 s transport timeout waiting for
this RES. Not proven: a real target probably reports `ATTACHED (0x20000)` in later
GET_PROCESS_INFO attributes, so set that bit after attaching.

### 8b. DETACH_PROCESS_RES (0x20/0x13): the 12-byte header alone
Validator `FUN_1400d01c0`: `result` must be 0, with 0 body bytes. The request is
`pid | resume_flag`, where `resume_flag` is `Detach(nResumeFlag)`.

### 8c. SUSPEND_PROCESS_RES (0x20/0x21): validator `FUN_1400d21f0`, consumer `FUN_140140270`
```
+0x0c u32 thread_count
+0x10 u32 n_failed
+0x14 ProcessInfo entry        self-sized, same layout as GET_PROCESS_INFO (decoded by FUN_1400f66f0).
                               FUN_140085b60 checks payload+0x18 (entry+4 = ProcessID) == pid (else 0x100010)
+0x14+P thread_count x basic ThreadInfo entries (0xAC, section 4b; FUN_1400cdeb0 walk; FUN_1400e49d0)
      then n_failed x u32 thread ids (bounds n_failed*4) -> "FailedThreads"
```
The validator requires at least **0x60 bytes starting at +0x0c** (8 bytes of counts plus a 0x58-byte
minimum process entry). The consumer builds the IStopNotification from the process entry and thread
list, sets `Status = 0` and `ThreadId = 0xffffffff`, and copies the failed ids.

### 8d. RESUME_PROCESS_RES (0x20/0x23): validator `FUN_1400d1e10`
Request: `pid | u32 n | n x u32 thread ids` (`FUN_1400d9430`).
Response: `+0x0c pid` (checked), `+0x10 u32 n`, `+0x14 n x u32`. The handler copies this array as
Resume's return value; the builder defaults to an empty list.

### 8e. SUSPEND_APPLICATION_RES (0x25) / RESUME_APPLICATION_RES (0x27)
`+0x0c u32 pid` only, and it is checked (validators `FUN_1400cfdf0` / `FUN_1400cfd90` require 4 bytes).

### 8f. ALLOC_EXEC_PAGE_RES (0x31) / ALLOC_DATA_PAGE_RES (0x33)
`+0x0c u32 pid` (checked), `+0x10 u32 address`. `FUN_1400f8490` / `FUN_1400f8230` store the address as
the return value. The validators require 8 bytes.

### 8g. GET_MEMBLK_INFO_RES (0x41): validator `FUN_1400d0f80`, decoder `FUN_1400f64d0`, names from formatter `FUN_1401ef640`
```
+0x0c u32 pid (checked) | +0x10 u32 count | +0x14 count x 0x48-byte records
validator: count*0x48 bytes present; if count != 0, entry[0]+0x00 == 0x48
REC+0x00 u32 size = 0x48
REC+0x04 u32 MemoryBlockID       -> [0]
REC+0x08 char[32] Name (NUL-terminated UTF-8)
REC+0x28 u32 Type                -> [0xd]
REC+0x2c u32 HeaderAddress       -> [0xb]
REC+0x30 u32 BlockSize           -> [0xc]
REC+0x34 u32 Attributes          -> [0xa]
REC+0x38 u32 (not read)
REC+0x3c u32 AllocatedSize       -> [0xe]
REC+0x40 u32 LowSize             -> [0xf]
REC+0x44 u32 HighSize            -> [0x10]
```

---

## 9. SYSTEM memory access (group 0x10)

### 9a. RDMEM (`GetMemory`; used by Razor's CProcessMemoryReader scan and struct reads)
Request (`FUN_1400d92c0`): `00 10 10 00 | u32 pid | u32 address | u32 size`.

**Chunking is done by psp2tm** (`FUN_14010b790`):
* If `size <= 0x10000`, one RDMEM is sent. The handler copies **`len` bytes from the response**, so
  a shorter `len` gives a shorter result.
* If `size > 0x10000`, it loops with `chunk = min(remaining, 0x10000)` at `address + done` and
  copies **exactly `chunk` bytes** from the response data pointer, whatever `len` says. The target
  must therefore return the full chunk. Any error on any chunk aborts the whole call.

Response (validator `FUN_1400d1580`):
```
+0x0c u32 pid        FUN_140085330: != request pid -> 0x100010
+0x10 u32 len        number of data bytes
+0x14 u8[len] data   bounds-checked for exactly len bytes (the builder adds pad4, which is harmless)
```
A 0x10000-byte chunk makes a 0x10014-byte payload, 0x10024 bytes with the DECI4 header. The mock's
NETMP registration advertises a per-protocol max payload of 0x10800, so a single frame would fit
that figure. Whether psp2tm's receive path accepts frames over 0x10000 is **not verified**. The
fragmentation path in section 1 is decoder-proven, so `fragment(payload)` (default 0x10000-byte
frames, giving 2 frames here) is the safe choice.

### 9b. WRMEM (`SetMemory`; Razor's SetRazorCaptureFlag writes 4 bytes)
Request (`FUN_1400d9db0`): `00 10 12 00 | u32 pid | u32 address | u32 len | data[len] | zero pad to 4`.
psp2tm does **not** chunk writes (`FUN_14013db60` makes a single call); the request packet must be
`< 0x10fed` bytes.
Response (validator `FUN_1400d2520`, 8 bytes required):
```
+0x0c u32 pid           != request pid -> 0x100010 (SCE 0x8004028b)
+0x10 u32 written_len   MUST equal the request len, else 0x100017 (SCE 0x80040292)
```

### 9c. GET_CONF (0x10/0x01)
`+0x0c u32 size` **must be 0x1c**, followed by 6 x u32 that `FUN_140109170` copies to object
+0x38..+0x4c (field names not recovered). Only implement this if Razor asks for it.

---

## 10. SYSTEM notifications the target pushes (group 0x10, codes 0xc0..0xd5)

Routing: when a frame doesn't match a pending transaction (section 1), `FUN_14012c040` checks
`payload+1 == 0x10` and passes it to `FUN_14011b140`. That function switches on `payload+2`,
validates, and forwards a TMAPI event to clients (`FUN_140068190`, "DEBUG_NOTIFY").
**None of the request handlers in sections 7-9 waits for a notification**, so attach, suspend,
read and write all complete without any. Razor might still react to the events on its own side
(e.g. `OnStopNotification`), which psp2tm cannot tell us.

Header: `b0(any) | 0x10 | code | 0 | seq 0 | u32 result=0 | body`. For STOP, +0x08 is a multi-part
key; use 0.
Where two validators exist, psp2tm tries the long form first, then the short form without the
timestamp. Names come from the IDebugEvents callbacks in `Interop.PSP2TMAPILib`.

| Code | Name | Validator(s) | Body at +0x0c |
|---|---|---|---|
| 0xc0 | STOP_NOTIFICATION | `FUN_1400d20f0` | ProcessInfo entry (>=0x58 bytes checked), `u32 Status`, `u32 ThreadId`, `u32 thread_count`, thread_count x basic ThreadInfo, `u64 tick timestamp` (optional) |
| 0xc2 | THREAD_CREATE | `FUN_1400d2340` (0x10) / `FUN_1400d23a0` (8) | `pid, tid, [u64 ts]` |
| 0xc4 | THREAD_EXIT | `FUN_1400d2400` (0x14) / `FUN_1400d2460` (0xc) | `pid, tid, exit_code, [u64 ts]` |
| 0xc6 | PROCESS_CREATE | `FUN_1400d1030` (0x10) / `FUN_1400d1090` (8) | `parent_pid, pid, [u64 ts]` |
| 0xc8 | PROCESS_EXIT | `FUN_1400d10f0` (0x10) / `FUN_1400d1150` (8) | `pid, exit_code, [u64 ts]` |
| 0xca | PROCESS_KILL | `FUN_1400d11b0` (0xc) / `FUN_1400d1210` (4) | `pid, [u64 ts]` |
| 0xcc | PRX_LOAD | `FUN_1400d1330` (>=0x34) / `FUN_1400d1460` (8) | long: `pid, modid, u64 ts, u16, char name@+0x12 (26), ..., u32@+0x2c, u32 nseg@+0x30, nsegx0x14 segments, u32 pathlen, path pad4, u32 n, n bytes`. Short: `pid, modid` |
| 0xce | PRX_UNLOAD | `FUN_1400d14c0` (0x10) / `FUN_1400d1520` (8) | `pid, modid, [u64 ts]` |
| 0xd0 | APPLICATION_SUSPENDED | `FUN_1400cfd30` (0xc) | `pid, u64 ts` |
| 0xd1 | APPLICATION_RESUMED | `FUN_1400cfcd0` (0xc) | `pid, u64 ts` |
| 0xd4 | LOADEXEC | `FUN_1400d12d0` (0x10) | `parent_pid, u64 ts, child_pid` |
| 0xd5 | LOADEXEC_FAIL | `FUN_1400d1270` (0x14) | `parent_pid, u64 ts, child_pid, u32 error` |

---

## 11. Builders added

- **Process:** `process_entry(p)`, `process_info_res`, `attach_process_res` (header only),
  `detach_process_res`, `suspend_process_res(b0, g, c, seq, process, threads, failed_ids)`,
  `resume_process_res(..., pid, ids)`, `app_suspend_res`, `app_resume_res`, `alloc_page_res`,
  `memblk_entry`, `memblk_info_res`.
- **System:** `get_conf_res`, `rdmem_res(b0, g, c, seq, pid, data)`, `wrmem_res(..., pid, length)`.
- **Notifications:** `stop_notification`, `thread_create_notification`, `thread_exit_notification`,
  `process_create_notification`, `process_exit_notification`, `process_kill_notification`,
  `prx_unload_notification`, `app_suspended_notification`, `app_resumed_notification`.
- **Dispatcher:** `build_reply(pay, ..., processes=[...], memblks_by_pid={...},
  read_mem=f(pid, addr, size), write_mem=f(pid, addr, data), alloc_page=f(pid, size, is_exec),
  conf=[6 u32])`.
  - ATTACH, DETACH, SUSPEND_APPLICATION, RESUME_APPLICATION and RESUME_PROCESS always succeed.
  - GET_PROCESS_INFO returns `None`, leaving it to the mock's existing handler, unless
    `processes` is passed.
  - RDMEM returns zeros unless `read_mem` is supplied.
  - WRMEM reports the full length written.
  - Always pass RDMEM results through `fragment()` before sending.

---
---

# Part C: the rest of the THREAD group (0x30) - sync primitives, suspend/resume, stack/app/fiber info

Same conventions and transaction rules as section 1. All RES names are from `FUN_140078cc0`.
These fill in the THREAD codes not covered in sections 4-5.

## 12. Message table

| Request payload | Name | RES | Transaction | Req builder | Validator | Consumer/TMAPI |
|---|---|---|---|---|---|---|
| `00 30 00 00 \| pid` | GET_THREAD_INFO | 0x01 | `FUN_140085000` | `FUN_1400d90c0` | `FUN_1400d0e40` | section 4 |
| `00 30 02 00 \| pid` | GET_THREAD_INFO_EX | 0x03 | `FUN_1400850d0` | `FUN_1400d9140` | `FUN_1400d0da0` | section 4 |
| `00 30 10 00 \| pid \| tid` | SUSPEND_THREAD | 0x11 | `FUN_140085c40` | `FUN_1400d9ad0` | `FUN_1400d22e0` | `IThread.Suspend` -> eThreadStatus |
| `00 30 12 00 \| pid \| tid` | RESUME_THREAD | 0x13 | `FUN_140085610` | `FUN_1400d94f0` | `FUN_1400d1eb0` | `IThread.Resume` |
| `00 30 14 00 \| pid` | GET_THREAD_NAMES | 0x15 | `FUN_1400851a0` | `FUN_1400d91c0` | `FUN_1400d0ee0` | section 4c |
| `00 30 16 00 \| pid` | GET_STACK_INFO | 0x17 | `FUN_140084f40` | `FUN_1400d8f40` | `FUN_1400d0c10` | `IProcess.StackInfo` |
| `00 30 20 00 \| pid \| nT \| types \| nID \| ids` | **GET_SYNC_INFO** (Razor's blocker) | 0x21 | `FUN_1400860e0` | `FUN_1400d8fc0` | `FUN_1400d0cb0` | `IProcess.SyncPrimitiveInfo` |
| `00 30 30 00 \| pid` | GET_APP_OBJECT_INFO | 0x31 | `FUN_1400840d0` | `FUN_1400d86a0` | `FUN_1400d0220` | `IProcess.ApplicationObjectInfo` |
| `00 30 32 00 \| pid` | GET_FIBER_STACK_INFO | 0x33 | `FUN_140084250` | `FUN_1400d8790` | `FUN_1400d0310` | fiber stacks |

All of these tolerate a **header-only error reply** (nonzero result), same as sections 1 and 7a; the
handler surfaces it as an SCE error and does not time out. So refusing any of them is safe.

### GET_THREAD_NAMES for the kernel pid (0x00010005): no special handling
`FUN_1400851a0` / `FUN_1400d0ee0` / `FUN_140111f50` never branch on the pid. The same 0x30/0x14
format (section 4c: count at +0x0c, then 0x24-byte `u32 id + char[32]` records, no pid echo) is used
for pid 0x10005 exactly as for a game pid. Just return that kernel process's own thread id/name list
(empty is fine).

## 13. GET_SYNC_INFO (the timeout Razor hit)

### 13a. Request `00 30 20 00 | u32 pid | u32 nTypes | nTypesxu32 | u32 nIDs | nIDsxu32`
Built by `FUN_1400d8fc0`. `Types` filters by primitive type and `IDs` by object id; **both empty
means "all"**, which is what `GET_SYNC_PRIM_INFO_LIST { Types:0{} IDs:0{} }` and the observed wire
`00 30 20 00 | 03 00 01 40 | 00 00 00 00 | 00 00 00 00` (pid 0x40010003, 0 types, 0 ids) send.

### 13b. Response: validator `FUN_1400d0cb0`, consumer `FUN_14010fa70`
```
+0x0c u32 pid            FUN_1400860e0 checks *ret == pid (else 0x100010). REQUIRED, 4 bytes.
+0x10 object[0], object[1], ...   packed, each self-sized. The validator walks them with
                                  FUN_140242a90 until the buffer runs out; count is implicit.
```
The validator needs 8 bytes at each object start, then `body_len` bytes, then advances
`ptr += body_len + 8`. **An empty list is just the 12-byte header + the pid word (a 16-byte
payload):** the first 8-byte read at +0x10 fails, the walk stops, count = 0. That is the minimal
reply that unblocks Razor.

Each object record:
```
OBJ+0x00 u32 type        a tag, NOT a byte length (see the type table below)
OBJ+0x04 u32 body_len    bytes after this word; the whole record is body_len + 8 bytes
OBJ+0x08 u32 (reserved)  word[2]; not read by the consumer
OBJ+0x0c ...             type-specific fields, starting at word[3]
```

**Type tags** (`FUN_14010fa70` switch, mapped to `ISyncPrimitiveInfo` collections):

| tag | primitive | tag | primitive |
|---|---|---|---|
| 0x10 | Semaphore | 0x52 | UltRWLock |
| 0x12 | UltMutex | 0x60 | ThreadEventHandler |
| 0x20 | Event | 0x70 | RWLock |
| 0x30 | Mutex | 0x81 | ConditionalVariable |
| 0x31 | LightWeightMutex | 0x90 | LightWeightConditionalVariable |
| 0x32 | UltQueueDataResourcePool | 0x92 | UltConditionalVariable |
| 0x40 | VariableLengthPool | 0xa0 | Timer |
| 0x41 | FixedLengthPool | 0xa1 | UltSemaphore |
| 0x42 | UltWaitingQueueResourcePool | 0xa2 | UltConditionalVariable (nested) |
| 0x43 | UltQueue | | |
| 0x50 | MessagePipe | | |
| 0x51 | Callback | | |

Field layouts differ per type (each `case` in `FUN_14010fa70`). The four common ones, verified from
the decoder (word indices are u32 from OBJ+0x00; strings are NUL-terminated UTF-8 in a fixed 32-byte
slot; "PID/TID pairs" is `u32 count` then countx`(pid, tid)`; "TID list" is `u32 count` then
countx`u32`):

* **Semaphore (0x10)** - `ISemaphore`: `[3]`Id `[4]`ProcessId `[5..0xc]`Name(32) `[0xd]`Attributes
  `[0xe]`ReferenceCount `[0xf]`InitialValue `[0x10]`Value `[0x11]`MaxValue `[0x12]`nPairs
  `[0x13..]`ProcessThreads pairs.
* **Event (0x20)** - `IEvent`: `[3]`Id `[4]`ProcessId `[5..0xc]`Name `[0xd]`Attributes
  `[0xe]`ReferenceCount `[0xf]`InitialValue `[0x10]`Value `[0x11]`nPairs `[0x12..]`ProcessThreads.
* **Mutex (0x30)** - `IMutex`: `[3]`Id `[4]`ProcessId `[5..0xc]`Name `[0xd]`Attributes
  `[0xe]`ReferenceCount `[0xf]`InitialValue `[0x10]`Value `[0x11]`ThreadOwnerId `[0x12]`nPairs
  `[0x13..]`ProcessThreads, then one **trailing u32** immediately after the pairs (read only if
  `nPairs*8 + 0x48 <= body_len`).
* **LightWeightMutex (0x31)** - `ILightWeightMutex` (no ProcessId): `[3]`Id `[4..0xb]`Name(32)
  `[0xc]`Attributes `[0xd]`WorkAddress `[0xe]`InitialValue `[0xf]`Value `[0x10]`ThreadOwnerId
  `[0x11]`nThreads `[0x12..]`Threads (TID list).

The other 17 layouts follow the same shape and can be read straight off `FUN_14010fa70` if a specific
type is ever needed. **Returning an empty list, or only the common types, is enough for Razor's name
gathering** - it just needs a non-timeout reply. One malformed record inside the list makes psp2tm
report `0x80040282` for the whole call (`FUN_14010fa70` case 0x52 shows the explicit check), so keep
each record well-formed or send an empty list.

## 14. Other THREAD responses

### 14a. SUSPEND_THREAD_RES (0x30/0x11): validator `FUN_1400d22e0`
Request `pid | tid`. Response `+0x0c pid`, `+0x10 tid`, `+0x14 u32 eThreadStatus`. Needs 0xc bytes.
`FUN_140085c40` checks pid (0x100010) and tid (0x100011).

### 14b. RESUME_THREAD_RES (0x30/0x13): validator `FUN_1400d1eb0`
Request `pid | tid`. Response `+0x0c pid`, `+0x10 tid`. Needs 8 bytes; pid and tid both checked.

### 14c. GET_STACK_INFO_RES (0x30/0x17): validator `FUN_1400d0c10`
`+0x0c u32 count`, `+0x10` count self-sized entries (each first u32 = size, walked by `FUN_1400cdeb0`).
**No pid echo.** Empty = header + `u32 0`. Entry layout not reversed; the builder passes raw bytes.

### 14d. GET_APP_OBJECT_INFO_RES (0x30/0x31): validator `FUN_1400d0220`
`+0x0c u32 count`, `+0x10 u32` (reserved; the validator checks 8 bytes here), `+0x14` count
self-sized entries. No pid echo. Empty = header + `u32 0` + `u32 0`.

### 14e. GET_FIBER_STACK_INFO_RES (0x30/0x33): validator `FUN_1400d0310`
`+0x0c u32 count`, `+0x10` count self-sized entries. No pid echo. Empty = header + `u32 0`.

## 15. Builders added (Part C)

- `sync_info_res(b0, group, code, seq, pid, objects=[])` - objects is a list of dicts (built by
  type) or raw record bytes; default empty. Per-type helpers: `sync_semaphore`, `sync_event`,
  `sync_mutex`, `sync_lwmutex`, and `sync_record(type_tag, words)` for any other tag. `SYNC_TYPES`
  maps every tag to its name.
- `suspend_thread_res(b0, g, c, seq, pid, tid, status)`, `resume_thread_res(..., pid, tid)`.
- `stack_info_res`, `app_object_info_res`, `fiber_stack_info_res` - empty lists by default; accept a
  list of raw entry-byte blobs.
- `build_reply` now also answers group 0x30 codes 0x10, 0x12, 0x16, 0x20, 0x30, 0x32. GET_SYNC_INFO
  uses `sync_objects_by_pid={pid: [...]}` (empty list if the pid is absent). SUSPEND/RESUME_THREAD
  echo the request's pid and tid; the stack/app/fiber codes return empty lists.
