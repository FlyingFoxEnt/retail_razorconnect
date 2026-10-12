# DECI4 DBGP `GET_PROCESS_INFO` response wire format (psp2tm.exe)

Reverse-engineered from decompiled `psp2tm.exe`. Every field width below is justified by a
specific read in the decoder chain. Key functions:

| Function | Role |
|---|---|
| `FUN_1400d1c80` | DECI4 frame accessor: verifies 16-byte header, `proto@frame+8 == 0x20000`, returns **payload = frame+0x10** |
| `FUN_140084bf0` | GET_PROCESS_INFO transaction: sends request, waits for `group=0x20 code=0x01`, calls the validator |
| `FUN_1400d0a20` | GET_PROCESS_INFO_RES **validator** (checks type/group/code/result/count and entry[0]) |
| `FUN_1400cdeb0` | generic entry-array bounds walker (each entry self-sized by its first word) |
| `FUN_14010dcc0` | **parser/caller**: builds the ProcessInfoList and maps errors |
| `FUN_1400e39d0` | builds `vector<ProcessInfo>` (0x88-byte elements) by looping `count` times over the entry array |
| `FUN_1400f66f0` | **single wire-entry -> ProcessInfo decoder** (proves every field offset/width) |
| `FUN_1401af520` | string reader: `MultiByteToWideChar(CP_UTF8=0xfde9, ..., len=-1)` -> NUL-terminated UTF-8 |
| `FUN_1401417a0` | target-error -> SCE-error map (`0x100007 -> 0x80040282`) |

---

## 1. Frame model: SINGLE frame containing `count` + array of entries

**It is one logical response = `[result][count][entry0..entryN-1]`, NOT one-frame-per-process, and
there is NO `Complete` terminator on the wire.**

Evidence:

* `FUN_1400e39d0` loops exactly `param_3 == count` times over ONE contiguous
  buffer, decoding one `ProcessInfo` per iteration and advancing `param_2 += *param_2` (each entry's
  own size word). It appends each 0x88-byte element to the output vector (`param_1[1] += 0x88`).
* `FUN_14010dcc0` calls the transaction once, then does a single
  `FUN_1400e39d0(&vec, local_res8+1, *local_res8, ...)` - `local_res8` is the pointer to the `count`
  word, `local_res8+1` is the first entry, `*local_res8` is the count - and assigns the whole vector
  into the `ProcessInfoList` at `object+0x38` (`FUN_1400f36e0`).
* The per-entry `Complete` byte (in-memory word `[0x20]`) is **hard-set to 1 by the decoder**
  (`FUN_1400f66f0`: `*(undefined *)(param_2 + 0x20) = 1`). It is not read from the
  wire, so it is neither a wire field nor a streaming terminator.

The "GET_PROCESS_INFO_RES logged 3 times" is DECI4 **transport fragmentation**, not multiple process
frames. `FUN_14008f540` receives the first frame and, while the payload
"more-fragments" flag is set (`(*(byte*)(payload+6) & 1) != 0` with `*(short*)(payload+4)==0`), keeps
receiving continuation frames and concatenates their payload bodies (`FUN_140242bd0(dst, frame+0xc,
len-0x1c)`) until a frame arrives with that flag clear. The reassembled buffer is then decoded once.
A small list (e.g. one process) fits in a single unfragmented frame (`payload+6 == 0`).

---

## 2. Exact byte layout

### 2a. DECI4 frame header (16 bytes) - from `FUN_1400d1c80`

```
+0x00  u24  total_len      total frame length INCLUDING this 16-byte header
+0x03  u8   0x40
+0x04  u16  flags
+0x06  u16  node
+0x08  u32  proto          MUST be 0x00020000 (DBGP)   <- checked: *(int*)(frame+8)==0x20000
+0x0c  u32  resv
+0x10  ...  payload        (FUN_1400d1c80: local_138 = lVar2 + 0x10)
```

### 2b. Response payload header (16 bytes) - from `FUN_1400d0a20`

All offsets are relative to the start of the payload (frame+0x10). `FUN_1400d0a20`:

```
+0x00  u8   type   = 0x00
+0x01  u8   group  = 0x20        <- *(char*)(p+1) != ' '  rejects
+0x02  u8   code   = 0x01        <- *(char*)(p+2) != 1    rejects
+0x03  u8   pad    = 0x00
+0x04  u16  seq    = 0x0000      (0 for a single/unfragmented response)
+0x06  u8   frag_flags = 0x00    (bit0 = "more fragments"; 0 = last/only frame)
+0x07  u8   (reserved) = 0x00
+0x08  u32  result = 0x00000000  MUST be 0  <- *(int*)(p+8) != 0 rejects; a nonzero SCE code here is surfaced
+0x0c  u32  count            number of ProcessInfo entries
+0x10  ...  entry[0], entry[1], ...   (packed; each entry self-sized)
```

For `count == 0` the validator returns success immediately (empty `ProcessInfoList:0{}`).
For `count != 0` the validator additionally requires (all on **entry[0]**):
* `*(u32)(p+0x10) > 0x57`   -> entry[0].size >= 0x58 (88)
* `*(u32)(p+0x50) == 0x14`  -> entry[0] byte 0x40 (StopReason block size) == 0x14
* `FUN_1400cdeb0(pkt, p+0x10, count)` -> every entry's `size` bytes are present in the packet.

### 2c. Entry array walking - from `FUN_1400cdeb0`

`FUN_1400cdeb0`: for each of `count` entries it verifies `*entry` bytes are
in-bounds, then advances `entry = (char*)entry + *entry`. So **each entry's first u32 is the total
byte length of that entry (including the length word), and entries are packed contiguously.**
`FUN_1400e39d0` advances identically (`param_2 += *param_2`).

### 2d. Per-process ENTRY layout - from `FUN_1400f66f0`

Offsets relative to the start of each entry. In-memory destination word index (`param_2[i]`, the
0x88-byte `ProcessInfo`) shown for cross-reference with the `FUN_1401efcd0` formatter.

```
ENTRY+0x00  u32   entry_size            *param_3  - total entry length; >=0x58, must cover the tail below
ENTRY+0x04  u32   ProcessID             param_3[1]  -> [0]  (*param_2 = param_3[1])
ENTRY+0x08  u32   Attributes            param_3[2]  -> [3]  (param_2[3] = param_3[2])
ENTRY+0x0c  char[36] ProcessName        NUL-terminated UTF-8, zero-padded; read via
                                        FUN_1401af520(param_3+3, -1, 0xfde9, param_2+4).
                                        FIXED 36 bytes: the next scalar (Affinity) is read from the
                                        hard-coded word 0xc (byte 0x30), so bytes 0x0c..0x2f are the
                                        name field. Max 35 chars + NUL. No length prefix.
ENTRY+0x30  u32   Affinity              param_3[0xc] -> [0x14]
ENTRY+0x34  u32   Entry                 param_3[0xd] -> [0x15]
ENTRY+0x38  u32   GUID                  param_3[0xe] -> [1]
ENTRY+0x3c  u32   ParentPID             param_3[0xf] -> [2]
ENTRY+0x40  u32   StopReason.size       param_3[0x10]  MUST == 0x14 (validated for entry[0]; not copied)
ENTRY+0x44  u32   StopReason.word0      param_3[0x11] -> [0x16]  (special: 0x00050001 is remapped to 0x00070000)
ENTRY+0x48  u32   StopReason.word1      param_3[0x12] -> [0x17]
ENTRY+0x4c  u32   StopReason.reserved   param_3[0x13]  (not copied)
ENTRY+0x50  u32   StopReason.word2      param_3[0x14] -> [0x18]
ENTRY+0x54  u32   ProcessPathname.len   param_3[0x15]  byte length of the pathname region (used only
                                        to locate the tail: tail = (len+3 & ~3) + 0x58)
ENTRY+0x58  char[len] ProcessPathname   NUL-terminated UTF-8; read via
                                        FUN_1401af520(param_3+0x16, -1, 0xfde9, param_2+0xc).
                                        VARIABLE length, starts at fixed byte 0x58; padded to 4 bytes.
ENTRY+0x58 + pad4(len):   (present only if len + 0x58 < entry_size)
        +0x00  u32  StartOfExidx        -> [0x19]
        +0x04  u32  EndOfExidx          -> [0x1a]
        +0x08  u32  StartOfExtab        -> [0x1b]
        +0x0c  u32  EndOfExtab          -> [0x1c]      (offset 0x64 = decompiled "100")
```

Notes proven by the decoder:
* **String encoding** (`FUN_1401af520`): `MultiByteToWideChar(codepage=0xfde9,
  0, src, len, ...)`. `0xfde9 = 65001 = CP_UTF8`. The decoder always passes `len = 0xffffffff (-1)`,
  which makes `MultiByteToWideChar` treat `src` as **NUL-terminated** (it then strips the NUL,
  `cchWideChar-1`). Therefore both strings are **plain NUL-terminated UTF-8 byte strings**, read from
  a fixed start offset. `ProcessName` has **no length prefix** (fixed 36-byte slot). `ProcessPathname`
  has a **u32 length at ENTRY+0x54** that is NOT used to bound the string read - it is only used to
  compute where the Exidx/Extab tail begins: `tail = ((len + 3) & ~3) + 0x58` (4-byte alignment pad).
* `ProcessTime` (in-memory `[0x1e..0x1f]`) is **not decoded from the wire** by `FUN_1400f66f0`.
* Element size is 0x88 bytes = 0x22 u32 words (`FUN_1400e39d0`: `param_1[1] + 0x88`; cleanup stride
  0x11 qwords in `FUN_14010dcc0`).

---

## 3. What `0x80040282` means / what triggers it

`0x80040282` is the SCE error the host reports when the response fails structural validation.

Chain:
1. `FUN_1400d0a20` returns NULL if any of: bad type/group/code, `result != 0`, `count` word missing,
   or (for `count != 0`) `entry[0].size <= 0x57`, `entry[0]@0x40 != 0x14`, or the entry-array bounds
   walk (`FUN_1400cdeb0`) fails.
2. `FUN_140084bf0` then returns internal code **`0x100007`**.
3. `FUN_1401417a0` maps **`case 0x100007: return 0x80040282;`**.
4. `FUN_14010dcc0` reports it via `FUN_1401006f0(...)`.

So the earlier populated attempt hit `0x80040282` because the entry layout was wrong - almost
certainly the entry `size` word was too small (`<= 0x57`), and/or the word at `ENTRY+0x40` was not
`0x14`, and/or entries did not pack correctly so the `size`-based walk ran out of bounds.
(Distinct from the earlier "result word @+8 = 2" test, which surfaced the target's own SCE code
"the entry does not exist"; that is the `result` field at payload+0x08, not this validation error.)

---

## 4. Concrete example - ONE process

`ProcessID=0x00010005`, `ProcessName="SceShell"`, `ProcessPathname="vs0:vsh/shell/eboot.bin"`,
all other fields 0.

Entry size chosen = **0x80** (128). Payload size = 0x10 + 0x80 = **0x90** (144). Frame total_len =
0x10 + 0x90 = **0xA0** (160).

### Payload (144 bytes) - annotated with ABSOLUTE payload offsets

(entry[0] starts at payload 0x10, so entry offset E = payload 0x10+E.)

```
payload  bytes                                            meaning
0x00     00 20 01 00                                       type=0 group=0x20 code=0x01 pad=0
0x04     00 00 00 00                                       seq=0, frag_flags=0, resv=0
0x08     00 00 00 00                                       result = 0  (REQUIRED)
0x0c     01 00 00 00                                       count = 1
0x10     80 00 00 00                                       [E+0x00] entry_size = 0x80  (>0x57 REQUIRED)
0x14     05 00 01 00                                       [E+0x04] ProcessID = 0x00010005
0x18     00 00 00 00                                       [E+0x08] Attributes = 0
0x1c     53 63 65 53 68 65 6c 6c 00 ...                    [E+0x0c] ProcessName "SceShell\0", 36-byte
0x1c..0x3f  (36 bytes: "SceShell" + NUL + zero pad)                 fixed field, ends at payload 0x40
0x40     00 00 00 00                                       [E+0x30] Affinity = 0
0x44     00 00 00 00                                       [E+0x34] Entry = 0
0x48     00 00 00 00                                       [E+0x38] GUID = 0
0x4c     00 00 00 00                                       [E+0x3c] ParentPID = 0
0x50     14 00 00 00                                       [E+0x40] StopReason.size = 0x14 (REQUIRED)
0x54     00 00 00 00                                       [E+0x44] StopReason.word0
0x58     00 00 00 00                                       [E+0x48] StopReason.word1
0x5c     00 00 00 00                                       [E+0x4c] StopReason.reserved
0x60     00 00 00 00                                       [E+0x50] StopReason.word2
0x64     18 00 00 00                                       [E+0x54] ProcessPathname.len = 0x18 (24)
0x68     76 73 30 3a 76 73 68 2f ...                       [E+0x58] "vs0:vsh/shell/eboot.bin\0"
0x68..0x7f  (24 bytes incl. NUL; tail = pad4(24)+E+0x58 = payload 0x80)
0x80     00 00 00 00                                       [E+0x70] StartOfExidx = 0
0x84     00 00 00 00                                       [E+0x74] EndOfExidx  = 0
0x88     00 00 00 00                                       [E+0x78] StartOfExtab = 0
0x8c     00 00 00 00                                       [E+0x7c] EndOfExtab  = 0
--- end entry[0] / end payload at 0x90 ---
```

### Full frame - copy/paste hex (160 bytes, authoritative)

```
# DECI4 header (16 bytes)
A0 00 00 40 00 00 00 00 00 00 02 00 00 00 00 00
# payload header (16 bytes)
00 20 01 00 00 00 00 00 00 00 00 00 01 00 00 00
# entry[0] (128 bytes)
80 00 00 00                                       # +0x10 entry_size = 0x80
05 00 01 00                                       # +0x14 ProcessID = 0x00010005
00 00 00 00                                       # +0x18 Attributes = 0
53 63 65 53 68 65 6C 6C 00 00 00 00 00 00 00 00   # +0x1c ProcessName "SceShell\0" ...
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   # +0x2c  ... (36-byte field)
00 00 00 00                                       # +0x3c  ... ends at +0x40
00 00 00 00                                       # +0x40 Affinity = 0
00 00 00 00                                       # +0x44 Entry = 0
00 00 00 00                                       # +0x48 GUID = 0
00 00 00 00                                       # +0x4c ParentPID = 0
14 00 00 00                                       # +0x50 StopReason.size = 0x14  (REQUIRED)
00 00 00 00                                       # +0x54 StopReason.word0
00 00 00 00                                       # +0x58 StopReason.word1
00 00 00 00                                       # +0x5c StopReason.reserved
00 00 00 00                                       # +0x60 StopReason.word2
18 00 00 00                                       # +0x64 ProcessPathname.len = 0x18 (24)
76 73 30 3A 76 73 68 2F 73 68 65 6C 6C 2F 65 62   # +0x68 "vs0:vsh/shell/eb
6F 6F 74 2E 62 69 6E 00                           # +0x78 oot.bin\0"  (24 bytes, ends +0x80)
00 00 00 00                                       # +0x80 StartOfExidx = 0
00 00 00 00                                       # +0x84 EndOfExidx  = 0
00 00 00 00                                       # +0x88 StartOfExtab = 0
00 00 00 00                                       # +0x8c EndOfExtab  = 0
```

Decoded result: `ProcessInfoList:1{ ... ProcessID:0x10005 GUID:0x0 ParentPID:0x0 Attributes:0x0
ProcessName:SceShell ProcessPathname:vs0:vsh/shell/eboot.bin Affinity:0x0 Entry:0x0 StopReason:{...}
... Complete:1 }` with no error.

### Multiple processes

Append additional entries immediately after entry[0] (at payload 0x90, 0x90+size1, ...), set
`count` accordingly, and grow `total_len`. Each entry is independently self-sized (its own
`entry_size` word first) and must itself satisfy `entry_size >= 0x58` and `entry@0x40 == 0x14` to be
well-formed (the validator strictly enforces those two only on entry[0], but the per-entry decoder
and bounds walk assume every entry follows the same layout). If the whole response exceeds one DECI4
frame, fragment it and set the `frag_flags` bit0 (payload+6) on every frame except the last.
