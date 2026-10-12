# DECI4 VCP (protocol 0x2b000) screen-capture wire format (psp2tm.exe + psp2tmapix64.dll)

VCP is the protocol behind Razor's `CaptureScreenShot`. Reverse-engineered from `psp2tm.exe`
(the DECI transport / command side) and `psp2tmapix64.dll` (the TMAPI `IProcess.ScreenShot`
side, which decides the pixel format and decompresses). All values little-endian.

Builders + a self-test with Python mirrors of psp2tm's validators: `tools/vcp_builders.py`.

## 0. What Razor sent and what it needs

The observed request was a 24-byte DECI4 frame, proto 0x2b000, payload `10 00 00 00 01 00 00 00`.
That is **VCP FREEZE_CMD (0x10)** with arg `0x00000001`. psp2tm logged
`CAPTURE_SCREEN_SHOT { View:0 }` then timed out (`0x8004021b`) waiting for **FREEZE_RES (0x11)**.

`CaptureScreenShot` is not one message. One `IProcess.ScreenShot(eView)` call (host stub
`FUN_180083860`, transport `FUN_1401461d0` <-> psp2tm `FUN_14008cb60`) runs three VCP round-trips:

1. **FREEZE on** - CMD 0x10 arg `view | 1` -> **FREEZE_RES 0x11** carrying the image metadata
   (ProcessId, VCount, Width, Height, PixelFormat). *This is the reply Razor is blocked on.*
2. **GET_COMP_PICT** - CMD 0x16 (no body) -> one or more **GET_COMP_PICT_RES 0x17** frames whose
   chunks concatenate into a **zlib-compressed** copy of the `Width*Height*4` pixels.
3. **FREEZE off** - CMD 0x10 arg `view` (bit0 clear) -> FREEZE_RES 0x11 again.

To make a screenshot succeed the mock must answer all three. (GET_STATUS 0x12/0x13, GET_PICT
0x14/0x15 exist by name only - this psp2tm build never issues them for a screenshot.)

## 1. VCP payload header (unlike DBGP)

There is **no** DBGP-style 12-byte block, no seq/frag words. The DECI4 frame header is the
usual 16 bytes (`u24 len | 0x40 | u16 flags | u16 node | u32 proto=0x2b000 | u32 resv`); the VCP
payload begins at frame+0x10 and is just:
```
+0x00 u32 code        VCP command / response code
+0x04 ...             for a CMD: an argument; for a RES: a result (0 = OK) then fields
```
Frame accessor `FUN_1400d7270`: verifies the 16-byte header, `proto == 0x2b000`, then returns
frame+0x10 (needs >=4 bytes for the code). `FUN_1400cf280(pkt, code)` fetches that payload and
checks `*payload == code`, i.e. the response is matched purely by its first u32.

## 2. Command / response codes (`FUN_1400d7110`)

| CMD | | RES | | in screenshot flow |
|---|---|---|---|---|
| 0x10 | FREEZE_CMD | 0x11 | FREEZE_RES | **yes** - metadata + freeze toggle |
| 0x12 | GET_STATUS_CMD | 0x13 | GET_STATUS_RES | no |
| 0x14 | GET_PICT_CMD | 0x15 | GET_PICT_RES | no (uncompressed variant, never issued) |
| 0x16 | GET_COMP_PICT_CMD | 0x17 | GET_COMP_PICT_RES | **yes** - compressed pixels, chunked |

RES code = CMD code | 1.

## 3. FREEZE (0x10) -> FREEZE_RES (0x11)

### 3a. Request (encoder `FUN_1400dfc30`)
```
+0x00 u32 code = 0x10
+0x04 u32 arg  = view | (freeze ? 1 : 0)
```
`view` is `eScreenShotView` (0 = ApplicationView, 0x10000 = SystemView). Razor's `View:0` with the
freeze-on bit gives `0x00000001`, exactly the observed bytes. Freeze-off (step 3) sends `arg = view`.

### 3b. Response (decoder `FUN_1400d71a0`, consumer `FUN_14008ca80`, DLL `FUN_180083860`)
```
+0x00 u32 code = 0x11
+0x04 u32 result        MUST be 0 for success (nonzero -> surfaced as an error, no metadata read)
+0x08 u32 ProcessId     -> ScreenShotData.ProcessId
+0x0c u32 VCount        -> ScreenShotData.VCount   (display frame counter; any value)
+0x10 u32 Width         -> ScreenShotData.Width     (also the W in the W*H*4 buffer reserve)
+0x14 u32 Height        -> ScreenShotData.Height    (the H)
+0x18 u32 PixelFormat   -> ScreenShotData.PixelFormat
```
Total 0x1c bytes. `FUN_1400d71a0` reads the result at +0x04; when it is 0 it then requires 0x18 (24)
more bytes - the 5 fields. `FUN_14008cb60` computes the pixel-buffer size as `Width * Height * 4`
before the GET_COMP_PICT loop, so Width and Height must be the real dimensions. For a PS Vita main
display use **Width = 960, Height = 544**.

**PixelFormat is A8B8G8R8.** `ePixelFormat` in `Interop.PSP2TMAPILib` has a single member
`A8B8G8R8 = 0`, and the DLL stub hard-writes `ScreenShotData.PixelFormat = 0` regardless of the wire
value, so send **0**. A8B8G8R8 means the 32-bit pixel is `0xAABBGGRR`, i.e. the bytes in memory are
**R, G, B, A** - plain RGBA byte order, 4 bytes per pixel.

## 4. GET_COMP_PICT (0x16) -> GET_COMP_PICT_RES (0x17): the pixels

### 4a. Request (encoder `FUN_1400dfcc0`)
```
+0x00 u32 code = 0x16      (no argument / body)
```

### 4b. Response frames (decoder `FUN_1400d7220`, consumer loop `FUN_14008cc20`)
psp2tm sends **one** GET_COMP_PICT_CMD, then reads a **sequence of GET_COMP_PICT_RES frames** (each a
complete DECI4 frame) until one sets the last flag. Each frame:
```
+0x00 u32 code = 0x17
+0x04 u32 result       0 = OK (nonzero aborts the whole GetMemory-style loop)
+0x08 u32 (unused)     psp2tm skips it; a total-size or index field. 0 is fine
+0x0c u32 last_flag    nonzero on the FINAL frame; that ends the receive loop
+0x10 u8[] chunk       compressed bytes; length = the rest of THIS frame's payload (implicit)
```
The consumer does `chunk = payload+0x10 .. end_of_payload` (`FUN_1402429c0` = end pointer - ptr) and
appends it, looping while `last_flag == 0`. So the chunk length per frame is whatever bytes follow
the 0x10-byte header, and the mock controls the split. After the last chunk psp2tm sets its internal
"compressed" flag to 1 unconditionally (`FUN_1400fa860`), so the concatenated stream is **always
treated as zlib** on the host.

### 4c. Compression (DLL `FUN_180083860` -> `FUN_180099f50`)
The reassembled bytes are a standard **zlib** stream (the DLL bundles zlib "1.2.8" and calls its
inflate). The DLL allocates `Width*Height*4` bytes and inflates into it; the result must be exactly
`Width*Height*4` bytes of A8B8G8R8 (R,G,B,A) pixels. Python `zlib.compress(rgba_bytes)` produces a
stream the DLL inflates correctly. (The DLL's other branch, for an uncompressed response, wraps the
raw bytes in a `SafeArrayCreateVector(VT_UI1,...)` - but psp2tm never takes that path here.)

### 4d. Fragmentation / frame size
Per-frame payload = `0x10 header + chunk`. psp2tm reserves a **0x11000-byte** receive buffer, so
keep each frame's payload under that; `vcp_builders.py` uses **0x10000 compressed bytes per frame**.
A 960x544x4 = ~2 MB image compresses to well under that for a typical frame and splits into a handful
of 0x17 frames; a pathological (incompressible) image would need ~32 frames of 0x10000. This is VCP's
**own** chunking (the `last_flag` field), independent of the DECI4 seq/frag mechanism used by DBGP.

## 5. Error handling / what psp2tm tolerates

* **FREEZE_RES with a nonzero result** (just `11 00 00 00 | <result>`, 8 bytes) is accepted by the
  decoder - `FUN_1400d71a0` reads the result first and, when it is nonzero, does not require the
  metadata. psp2tm maps the result through `FUN_1401417a0` and reports it; **it does not time out**.
  So a header-only VCP error is safe transport-wise. But **Razor aborts the whole capture on a failed
  screenshot**, so to actually capture you must return a successful FREEZE_RES + pixels.
* A GET_COMP_PICT_RES with nonzero result aborts the pixel loop the same way.
* If no matching RES arrives at all, psp2tm times out after 5 s and returns `0x8004021b` (the generic
  code, exactly what was logged) - that was the original symptom.

## 6. Builders (`tools/vcp_builders.py`)

- `freeze_res(pid, vcount, width=960, height=544, pixel_format=0, result=0)` - one FREEZE_RES payload
  (or an 8-byte error payload when `result != 0`).
- `comp_pict_frames(pixels_rgba, chunk=0x10000)` - zlib-compresses `pixels_rgba` (must be
  `width*height*4` bytes, R,G,B,A order) and returns the list of GET_COMP_PICT_RES payloads, last flag
  set on the final one.
- `get_pict_frames(pixels_rgba)` - uncompressed GET_PICT_RES payloads (completeness only; unused).
- `screenshot_res(request_payload, width=960, height=544, pixels_rgba=None, pid=0, vcount=0)` - the
  goal function. Dispatches on the request's first u32: FREEZE (0x10) -> `[freeze_res]`;
  GET_COMP_PICT (0x16) -> `comp_pict_frames(...)`; GET_PICT (0x14) -> `get_pict_frames(...)`;
  GET_STATUS (0x12) -> a minimal `[GET_STATUS_RES]`. Returns a **list of payloads**, one DECI4 frame
  each. If `pixels_rgba` is omitted for a picture request it makes a black image.
- `error_res(request_payload, result=0x1b)` - header-only error for the matching RES code.

Usage in the mock's VCP handler (proto 0x2b000):
```python
from vcp_builders import screenshot_res
for payload in screenshot_res(vcp_payload, 960, 544, pixels_rgba=my_rgba, pid=game_pid):
    send(frame(payload, node, 0x2b000, flags))
```
Send the FREEZE_RES for the 0x10 request, then the whole GET_COMP_PICT_RES list for the 0x16 request,
then FREEZE_RES again for the 0x10 (freeze-off) request. `pixels_rgba` is A8B8G8R8 (R,G,B,A) and must
be exactly `width*height*4` bytes.
