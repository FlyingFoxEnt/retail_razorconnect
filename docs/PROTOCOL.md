# Target Manager protocol (DECI4, TSMP, NETMP)

A mock target is found and listed by Target Manager: `psp2ctrl find 127.0.0.1` returns a populated DevKit row
and `psp2ctrl list` shows it persistently:

```
HardwareId                       Name     Host      ConnectionInfo NetMgr  CP      Kernel
00000000000000000000000100160afa MockVita 127.0.0.1                0.0.0.0 0.0.0.0 0.000
```

Working implementation: `tools/mock16.py` (run `python mock16.py <seconds> M`).
It logs the full 12-frame exchange as hex dumps.

## Corrections to the older sections below

Sections further down were written before the protocol was finished and contain two
**disproven** claims. Trust this banner over them.

1. **`CONNECT_RES` is 24 bytes with a 4-byte body - there is no 0x60 block and no
   "6-entry preamble".** That theory came from `FUN_1400d42d0`, which is a **LOADP**
   (protocol 0x24000) decoder, not NETMP. The real NETMP `CONNECT_RES` decoder is
   `FUN_1400d4ba0` and it reads exactly 4 body bytes.
   Accepted bytes: `18 00 00 40 | 00 00 00 40 | 00 10 00 00 | 00 00 00 00 | 01 00 00 00 | 00 00 00 00`

2. **`TARGET_LIST_RES` entries are 4-byte HWIDs, not 16 bytes.** Body is
   `u32 result; u16 count; u16 pad; count x u32 HWID` (`FUN_1400d6ee0` reads `count<<2`).

3. **NETMP has no `arg`/`seq` fields** (unlike TSMP). Payload is just the code word, then body.

## What actually establishes "connected"

There is no connected flag. The state *is* the two maps that **`PROTO_LIST_RES`** fills:
protocol->node (`FUN_14008db60`) and protocol->version (`FUN_14008ea90`). After that the frame
writer puts `map[proto]` in header byte 6 of every outgoing frame.

`PROTO_LIST_RES` body: `u32 result=0; u32 count;` then count x 16-byte descriptor:
```
+0x00 u32 protocol number
+0x04 u32 version        must be >= 0x03030000 (use 0x03600000)
+0x08 u32 limit          never read (0x10800 is fine)
+0x0c u16 node           MUST be non-zero or the entry is silently dropped
+0x0e u16 pad
```

## Two bugs that cost the earlier attempts

- **`mock14.py` crashed on 20-byte frames.** It unpacked a 12-byte TSMP payload at offset 16;
  `PROTO_LIST_CMD`/`DISCONNECT_CMD`/`REGISTERED_LIST_CMD` are 20-byte frames, so `struct.error`
  (neither `socket.timeout` nor `OSError`) killed the session thread. The host was waiting on a
  dead thread. Always catch broad `Exception` in the session loop.
- **Client timeout is ~2.0s, not 5s.** psp2tm waits 5.0s (`FUN_140090990`) but TMAPI/psp2ctrl
  gives up at ~2.005s with `NO_CONNECT`. Answer well inside 2 seconds.
- **Add a CPUP stub** (protocol 0x3000, code 0 -> code 1, result 0) or you eat a 5s stall.

## Console output (TTYP)

Target **pushes** unsolicited on protocol `0x800300NN` (NN = stream). No poll, no enable, no
response expected. Dispatcher `FUN_140131660` masks with `0xFFFFFF00` and routes `0x80030000`
to `FUN_140134850`, which computes the stream as `proto + 0x7ffd0000` (i.e. NN) and keys its
text reassembly on (stream, processId, threadId) - a line split across frames is joined.

NN is `PSP2TMAPILib.eConsoleOutputStream` (read from `Interop.PSP2TMAPILib.dll`):

| NN | stream | NN | stream |
|---|---|---|---|
| 0x00 | STDOUT | 0x81 | CP |
| 0x01 | STDERR | 0x90-0x93 | KERNEL0-3 |
| 0x02-0x07 | USER2-7 | 0xC0-0xC7 | TMAPI0-7 |

`psp2ctrl console user` shows only STDOUT, STDERR and USER2-7; `console all` adds the rest.
28-byte payload header then UTF-8 text:
```
+0x00 u16 source      0=NONE 0x1000=USER 0x8000=KERNEL
+0x02 u8  flags       MUST be 0 (bit0 -> discarded, bit1 -> no text delivered)
+0x03 u8  reserved
+0x04 u32 processId
+0x08 u32 threadId
+0x0c u32 sequence
+0x10 u64 tickTimestamp
+0x18 u32 textLength  must equal total_length - 44
+0x1c     text
```

---

# DECI4P / TSMP protocol - as recovered from psp2tm.exe

Everything here is derived from Ghidra decompilation of
`Target Manager Server\bin\psp2tm.exe` (3.60.0.2) plus live probing against the
running service. Ghidra project and scripts are in `ghidra/`; the mocks are in `tools/`.

Status: **the handshake, the frame format and the TSMP message vocabulary are solved.**
A mock on TCP 8540 gets Target Manager to list-and-select a fabricated DevKit by HWID.
It does not yet complete the post-select exchange, so the target is not listed in
Neighborhood yet.

---

## 1. Transport

TCP port **8540**, on the *host* that owns targets. `psp2ctrl find <host>` = "ask the
Network Manager on `<host>` for its DevKits", so a mock on 8540 impersonates that service.

## 2. Handshake - `FUN_1400e01b0`

```
server -> target :  "DECI"                     4 bytes
target -> server :  15 A3 F8 E1                u32 BIG-ENDIAN magic 0x15A3F8E1
target -> server :  00 00 00 40                u32 BIG-ENDIAN total length 0x40
target -> server :  <56 bytes>                 14 x u32 BIG-ENDIAN
```

The 56-byte payload is **not validated** - all zeros is accepted. On success psp2tm
launches its `CPSP2Socket` thread and the session begins.

Wrong magic => instant FIN. This was the wall that blocked everything before.

## 3. Frame format - writer `FUN_1400db470`, reader `FUN_1400e0770`

All little-endian from here on (note the reversal from the big-endian hello).

```
offset  size  field
0       3     total length (u24)     must satisfy 16 <= len <= 0x11000
3       1     0x40                   reader asserts == '@'
4       2     flags                  0 observed
6       2     node id                0x4000 from host; echo it back
8       4     protocol               0x2000 = TSMP
12      4     reserved               0
```

Reader logic, verbatim in effect:

```c
recv(hdr,0x10);
if (hdr[3]=='@' && len < 0x11001 && len > 15) recv(body, len-0x10);
```

## 4. TSMP payload - builder `FUN_1400db780`

```
offset  size  field
16      1     type
17      1     code          even = CMD, odd = RES
18      2     pad
20      4     arg
24      4     seq
28      ...   body
```

**Exception:** the host's identity frame uses an 8-byte payload header
(`type, code, pad, u32 strlen`) followed immediately by the string - there is no `seq`.
Observed: `type=0 code=0 strlen=0x28 "<user>@<machine>,TargetManager"`.

## 5. Message vocabulary - `FUN_14008d1b0`

| type | group | codes |
|---|---|---|
| 0 | ERROR | 0 |
| 1 | LIST | 0/1 TARGET_LIST, 2/3 UDP_FIND_TARGET |
| 2 | SELECT | 0/1 TARGET_SELECT, 2/3 TARGET_DESELECT |
| 3 | INFO | 0/1 HW_INFO, 2/3 SET_STICKY_NOTE, 4/5 SW_INFO, 6/7 GET_EXPIRY_TIME, 8/9 GET_USB_INFO |
| 4 | CONTROL | 0/1 POWER_STATUS, 2/3 POWER_CONTROL, 4/5 UPDATE_ACTIVATION |
| 5 | SETTINGS | 0/1 GET, 2/3 GET_CURRENT, 4/5 SET, 6/7 UIFILE, 8/9 XML |
| 6 | NOTIFICATIONS | TOOL, SETTINGS_ACCEPTED |

## 6. Response body sizes - decoders (callers of `FUN_1400cf160`)

`FUN_1400cf160(msg,type,code)` validates the header; `FUN_140242a90(s,p,N)` reads N body
bytes and fails the decode if short. "var-blob" = `u32 field; u16 len; u16 pad; u8 data[len]`
read by `FUN_1400cdeb0`.

| type.code | message | body |
|---|---|---|
| 0.0 | ERROR | 4 |
| 1.3 | UDP_FIND_TARGET_RES | 4 |
| 2.1 | TARGET_SELECT_RES | 4 |
| 2.3 | TARGET_DESELECT_RES | 4 |
| 3.1 | HW_INFO_RES | 8 + var-blob |
| 3.5 | SW_INFO_RES | 8 + var-blob |
| 3.7 | GET_EXPIRY_TIME_RES | 8 |
| 3.9 | GET_USB_INFO_RES | 0x30 |
| 4.1 | POWER_STATUS_RES | 8 |
| 4.3 | POWER_CONTROL_RES | 4 |
| 4.5 | UPDATE_ACTIVATION_RES | 4 |
| 5.1 | GET_SETTINGS_RES | 8 + var-blob |
| 5.3 | GET_CURRENT_SETTINGS_RES | 8 + var-blob |
| 5.9 | GET_SETTINGS_XML_RES | 8 |
| 7.1 | - | 0xc |

There is **no decoder for 1.1 (TARGET_LIST_RES)** in that family; its body was found
empirically instead:

```
u32 status (0)
u32 count
entry[count]      16 bytes each; entry[0..3] = HWID (u32)
```

Proof it is right: with `count=1, entry={HWID,1,0,0}` the host answers with
`TARGET_SELECT_CMD arg=0x160AFA` - 1444602, exactly the HWID we advertised.

## 7. Observed session

```
<- TARGET_LIST_CMD     t1.c0 arg=0        seq=0
-> TARGET_LIST_RES     t1.c1  status=0 count=1 entry(HWID)
<- TARGET_SELECT_CMD   t2.c0 arg=<HWID>   seq=1
-> TARGET_SELECT_RES   t2.c1  status=0
<- identity frame      t0.c0 strlen=0x28  "<user>@<machine>,TargetManager"
   ... 5 second stall ...
<- "TM has timed out!" t5 frame
<- TARGET_DESELECT_CMD t2.c2
```

## 8. The remaining gap

After the host sends its identity it waits ~5s for something we are not sending, then
declares `TM has timed out!` and deselects. Tried and rejected: replying to the identity
frame with a mirrored identity; not replying at all; pushing unsolicited HW_INFO/SW_INFO.

`psp2ctrl` error progression, which is the useful oracle:

| error | meaning |
|---|---|
| `Couldn't connect to PSP2 Network Manager` | nothing listening / handshake failed |
| `TMAPI_COMMS_ERR_TIMEOUT_TOOL_MANAGER` | handshake OK, no valid TSMP reply |
| `TMAPI_COMMS_ERR_DECODE` | right message type, wrong body |
| `No DevKits found on <ip>` | body parsed, list empty |
| `TMAPI_COMMS_ERR_TIMEOUT_NET_MANAGER` | list+select worked, post-select stall |

### Next steps, cheapest first

1. Decompile the host state machine that runs after `TARGET_SELECT_RES` - find what it
   blocks on. Start from the callers of the identity-frame builder and the 5s timer that
   emits "TM has timed out!" (`FUN_140089bb0`, counter at `+0x264`, timer at `+0x2e0`).
2. Raise `<LogLevel>` in `%LOCALAPPDATA%\SCE\PSP2TM\Server.xml` and restart the service -
   psp2tm has a categorised logger (DECI / SOCKET / TARGET / FSD, from `FUN_14007a800`)
   and its `ServiceLog.log` already proved decisive once by naming "TSMP Type Unhandled".
3. Only then worry about HWID validity and activation.

## 9. Caution

Malformed frames crashed psp2tm several times, leaving ~78 MB dumps in
`%LOCALAPPDATA%\SCE\PSP2TM\`. Delete them if they accumulate.

---

# Update: NETMP (protocol 0x1000) and what still blocks listing

Raising `<LogLevel>` to 5 in `%LOCALAPPDATA%\SCE\PSP2TM\Server.xml` (backup:
`Server.xml.bak-loglevel`) made psp2tm narrate the protocol. That is how everything below
was found - it is by far the most effective tool in this exercise.

## There are TWO protocols on the same socket

| proto | name | role |
|---|---|---|
| 0x2000 | TSMP | target system management: list, select, HW/SW info, power |
| 0x1000 | NETMP | network management: connect/register/protocol-list |

**The reply must echo the protocol id of the frame it answers.** Hardcoding 0x2000 was a real
bug - the host logged `*** TIMEOUT: Proto:0x1000` while we happily answered on 0x2000.

## NETMP codes (single code byte, not type+code) - from psp2tm's name table

```
 0 CONNECT_CMD        1 CONNECT_RES
 2 DISCONNECT_CMD     3 DISCONNECT_RES
 4 REGISTER_CMD       5 REGISTER_RES
 6 UNREGISTER_CMD     7 UNREGISTER_RES
 8 REGISTERED_LIST_CMD  9 REGISTERED_LIST_RES
10 PROTO_LIST_CMD    11 PROTO_LIST_RES
12 FORCE_DISCONNECT_CMD 13 FORCE_DISCONNECT_RES
14 FORCE_UNREGISTER_CMD 15 FORCE_UNREGISTER_RES
```

The frame the host sends on 0x1000 right after `TARGET_SELECT_RES` is `CONNECT_CMD` carrying
`"<user>@<machine>,TargetManager"`, laid out as
`u8 code | u8 pad | u16 pad | u32 strlen | char str[]` (8-byte payload header, no seq).

## CONNECT_RES first word is an SCE error enum

Sweeping the first body word and reading psp2ctrl's message back:

| value | host reports |
|---|---|
| 0 | (no error) - but connection still not established |
| 1 | Insufficient resources |
| 2 | The entry does not exist |
| 3 | The entry already exists |
| 4 | The resource is busy |
| 5 | Operation is not permitted |
| 6 | The value is out of acceptable range |
| 8 | The function is not implemented |

So 0 = success. With 0 the NETMP timeout disappears and psp2ctrl reports
`TMAPI_COMMS_ERR_NO_CONNECT` - the connect is decoded but the session is still not
considered established, so `CONNECT_RES` needs more than a result word (a node/session id
and/or a following REGISTER exchange). That is the current frontier.

## Neighborhood's discovery is UDP, not this TCP path

With the Add Network Target dialog scanning, the log fills with
`Decoding TSMP response TSMP_TYPE_LIST_CODE_UDP_FIND_TARGET_RES` and `CANCEL_FIND_TARGETS`.
So the dialog's "Discovered targets" list is populated over **UDP** (`UDP_FIND_TARGET`,
TSMP type 1 code 2/3), which the TCP-only mock never answers. Typing an address into the
dialog uses the TCP path we have solved; the auto-discovery list needs a UDP responder.

### Next steps

1. Add a **UDP listener** answering `UDP_FIND_TARGET_CMD` with `UDP_FIND_TARGET_RES`
   (4-byte body per the decoder table) so the target self-announces to the dialog.
2. Finish `NETMP_CONNECT_RES` - decompile the host handler that decides "connected", and
   implement the `REGISTER` / `PROTO_LIST` exchange that presumably follows.
3. Then `HW_INFO` / `SW_INFO` / `STICKY_NOTE` fill in the columns Neighborhood displays.

### Current mock status

`tools/old/mock12.py` reaches: handshake -> TARGET_LIST_RES (advertising HWID 1444602) ->
host SELECTs that HWID -> TARGET_SELECT_RES -> NETMP CONNECT_CMD -> CONNECT_RES(0).
Remaining error: `TMAPI_COMMS_ERR_NO_CONNECT`.

Run: `python tools/old/mock12.py <seconds> <hwid> 1 00000000`

---

# Update 2: UDP discovery solved; NETMP connect still open

## UDP discovery (solved, captured on the wire)

Target Manager broadcasts to **UDP port 8540** from an ephemeral port, to every subnet in
Neighborhood's "Set Discovery Ranges" list. The datagram is an ordinary DECI frame:

```
20 00 00 40 | 00 00 00 00 | 00 20 00 00 | 00 00 00 00
01 02 00 00 | 00 00 00 00 | 00 00 00 00 | <u32 attempt>

len=0x20  marker=0x40  flags=0  node=0x0000  proto=0x2000 (TSMP)  resv=0
type=1 code=2 = UDP_FIND_TARGET_CMD, arg=0, seq=0, 4-byte body = attempt counter
```

Reply with `type=1 code=3` (`UDP_FIND_TARGET_RES`), 4-byte body, sent back to the source
address and port, echoing node/flags. psp2tm confirms it parses these:
`DECI Decoding TSMP response TSMP_TYPE_LIST_CODE_UDP_FIND_TARGET_RES`.

Implemented in `tools/old/mock13.py` / `tools/old/mock14.py` (combined TCP+UDP server).
Capture tool: `tools/udp_probe.py`.

Note the discovery ranges Neighborhood scans are configurable in its dialog; on this machine
they are 172.24.16.0/20, 192.168.1.0/24, 10.0.10.253, 127.0.0.1.

## NETMP connect - how far it gets

The host's NETMP exchange, per its own log:

```
DECI Decoding NETMP response NETMP_CODE_CONNECT_RES      <- our CONNECT_RES is decoded
DECI Waiting for NETMP response NETMP_CODE_PROTO_LIST_RES
```

Critically, **no PROTO_LIST_CMD is ever sent**. The protocol list is expected *inside*
`CONNECT_RES`, which matches its decoder `FUN_1400d42d0`:

```c
lVar2 = validate(msg, 1, 0);          // (RES code, CMD code) = CONNECT_RES
read(msg, lVar2+4, 4);                // u32 result
if (result == 0) {
    read(msg, lVar2+4, 0x60);         // 0x60-byte block
    count = *(u32*)(lVar2+0x60);      // count at body+0x5c
    FUN_1400ce100(msg, lVar2+100, count);   // array at body+0x60, 0x10-byte entries
    lVar4 = count + 6;
    lVar2 = lVar2 + 8 + lVar4*0x10;   // ...and more after the array
    read(msg, lVar2, ...);
}
```

The NETMP decoder table (callers of validator `FUN_1400ce940`, args = RES code, CMD code):

| args | message | reads |
|---|---|---|
| (1,0) | CONNECT_RES | 4, 0x60, 0x10-entries (var) |
| (5,4) | REGISTER_RES | 4, 8 |
| (7,6) | UNREGISTER_RES | 4, 0x18 |
| (9,8) | REGISTERED_LIST_RES | 4, 0x18 |

Tried in `mock14.py`: `result=0`, a 0x60 block with `count=2` at +0x5c, and two 16-byte
protocol descriptors `{proto, version, limit, status}` for 0x1000 and 0x2000 (128 bytes
total). Host still ends at `TMAPI_COMMS_ERR_NO_CONNECT`, so either the entry layout or the
trailing section after the array is wrong.

### Where to pick this up

1. Decompile `FUN_1400ce100` (the array reader) to get the exact 16-byte entry layout, and
   the tail read after `lVar2 + 8 + (count+6)*0x10` - that offset arithmetic implies a fixed
   6-entry preamble which our body does not supply.
2. Alternatively find psp2tm's own **encoder** for CONNECT_RES (it acts as a Network Manager
   for local devkits, so it builds this message too) - reading the writer is easier than
   inferring from the reader.
3. `IEventCustomProtocol.OnStatusProtocol(uProtocol, uProtocolVersion, uProtocolLimit,
   uTargetNode, uStatus)` in the TMAPI interop is a strong hint at the descriptor fields.

---

# DBGP (0x20000) - GET_PROCESS_INFO only (for the Console Output GUI)

Sony's Console Output GUI (`PSP2ConsoleOutput.exe`) calls `GetProcessInfoSnapshot` before it
will show the TTY panel; with no DBGP node advertised it fails `TMAPI_COMMS_ERR_NO_CONNECT` and
the window stays empty (the `psp2ctrl console` CLI does not call this and works without it).

We advertise DBGP and answer only `DBGP_GROUP_PROCESS` (group 0x20) `GET_PROCESS_INFO` (code
0x00 -> RES 0x01). Full wire format, reverse-engineered from `psp2tm.exe`'s decoder chain
(`FUN_1400d0a20` validator, `FUN_1400f66f0` entry decoder) and verified against the live TMAPI
decoder, is in `DBGP_PROCINFO_FORMAT.md`. Request is 4 bytes `00 20 00 00`. Response payload:

```
00 20 01 00 | u16 seq, u8 frag=0, u8 rsv | u32 result=0 | u32 count | entries...
entry: u32 size(>=0x58) | u32 pid | u32 attrs | char name[36] (NUL-term, fixed) |
       u32 affinity | u32 entry | u32 guid | u32 ppid | u32 0x14 | u32 sr[4] |
       u32 pathlen | char path[pad4(pathlen)] | u32 exidxStart,exidxEnd,extabStart,extabEnd
```

`tools/mock_dbg.py` is the PC harness used to solve it (drive with `psp2ctrl` / TMAPI against a
127.0.0.1 target). The plugin fills the list from `sceKernelGetProcessId` +
`sceAppMgrGetPidListForShell`, naming each pid via `sceKernelGetProcessTitleId`. The rest of
DBGP (attach / threads / memory / breakpoints - the actual debugger) is not implemented.
