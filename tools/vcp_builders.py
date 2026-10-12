"""VCP (DECI4 protocol 0x2b000, "Video Capture Protocol") response builders for
psp2tm.exe's screen-capture path. VCP is what Razor's CaptureScreenShot uses.

Every function returns a VCP *payload* (the bytes after the 16-byte DECI4 frame
header). Wrap each with the mock's frame(payload, node, 0x2b000, flags). Some
commands answer with several frames (a list of payloads), one DECI4 frame each.

VCP payload header (NOT like DBGP; there is no seq/frag/12-byte block):
    +0x00 u32 code        the VCP command/response code (see CODES)
    ...   command-specific
For a RES the second word is a result (0 = OK); for a CMD it is an argument.

Codes (psp2tm FUN_1400d7110):
    0x10 FREEZE_CMD        0x11 FREEZE_RES        (screenshot metadata + freeze)
    0x12 GET_STATUS_CMD    0x13 GET_STATUS_RES    (not used by the screenshot path)
    0x14 GET_PICT_CMD      0x15 GET_PICT_RES      (uncompressed; this psp2tm build never sends it)
    0x16 GET_COMP_PICT_CMD 0x17 GET_COMP_PICT_RES (zlib-compressed pixels, chunked)

Layouts and the psp2tm/TMAPI functions that prove them: ../docs/VCP_FORMAT.md
"""
import struct
import zlib

__all__ = [
    "vcp_header", "freeze_res", "comp_pict_frames", "get_pict_frames",
    "screenshot_res", "error_res",
    "PIXFMT_A8B8G8R8", "CODES", "VITA_W", "VITA_H",
]

CODES = {
    0x10: "FREEZE_CMD", 0x11: "FREEZE_RES", 0x12: "GET_STATUS_CMD", 0x13: "GET_STATUS_RES",
    0x14: "GET_PICT_CMD", 0x15: "GET_PICT_RES", 0x16: "GET_COMP_PICT_CMD", 0x17: "GET_COMP_PICT_RES",
}

PIXFMT_A8B8G8R8 = 0        # ePixelFormat.A8B8G8R8, the only member. Memory bytes are R,G,B,A.
VITA_W, VITA_H = 960, 544  # PS Vita main display

# psp2tm reserves a 0x11000-byte receive buffer; keep each frame's payload well under it.
COMP_CHUNK = 0x10000       # compressed bytes per GET_COMP_PICT_RES frame


def vcp_header(code, result_or_arg=0):
    return struct.pack("<II", code & 0xFFFFFFFF, result_or_arg & 0xFFFFFFFF)


def freeze_res(pid=0, vcount=0, width=VITA_W, height=VITA_H, pixel_format=PIXFMT_A8B8G8R8,
               result=0):
    """FREEZE_RES (0x11), the reply psp2tm waits for after FREEZE_CMD (Razor's
    CaptureScreenShot maps to FREEZE with arg = view | 1). Decoder FUN_1400d71a0:
      +0x00 u32 code = 0x11
      +0x04 u32 result          MUST be 0 for success (nonzero is surfaced as an error)
      +0x08 u32 ProcessId       ScreenShotData.ProcessId
      +0x0c u32 VCount          ScreenShotData.VCount (frame counter; any value)
      +0x10 u32 Width           used as W in the W*H*4 pixel-buffer reserve (FUN_14008cb60)
      +0x14 u32 Height          used as H
      +0x18 u32 PixelFormat     ScreenShotData.PixelFormat; A8B8G8R8 = 0
    The decoder requires result at +0x04, then 0x18 (24) more bytes when result == 0.
    An error reply may be just code+result (8 bytes)."""
    if result != 0:
        return vcp_header(0x11, result)
    return vcp_header(0x11, 0) + struct.pack("<5I", pid, vcount, width, height, pixel_format)


def _comp_res(chunk, last, word1=0, result=0):
    """One GET_COMP_PICT_RES (0x17) frame. Decoder FUN_1400d7220 / consumer FUN_14008cc20:
      +0x00 u32 code = 0x17
      +0x04 u32 result       0 = OK
      +0x08 u32 (unused by psp2tm; total size or index - 0 is fine)
      +0x0c u32 last_flag     nonzero on the FINAL frame (stops the receive loop)
      +0x10 u8[] chunk        length = the rest of this frame's payload (implicit)
    """
    return vcp_header(0x17, result) + struct.pack("<II", word1, 1 if last else 0) + bytes(chunk)


def comp_pict_frames(pixels_rgba, chunk=COMP_CHUNK):
    """The frames for one GET_COMP_PICT_CMD (0x16): zlib-compress the raw pixels, then split
    the compressed stream into GET_COMP_PICT_RES frames. psp2tm concatenates the chunks and
    the TMAPI DLL zlib-inflates them back to width*height*4 bytes (FUN_180099f50, "1.2.8").
    `pixels_rgba` MUST be width*height*4 bytes in A8B8G8R8 memory order (R,G,B,A per pixel).
    Returns a list of payloads; the mock sends them as back-to-back VCP frames after the CMD."""
    comp = zlib.compress(bytes(pixels_rgba), 6)
    if not comp:                                   # never empty, but stay safe
        return [_comp_res(b"", True)]
    parts = [comp[i:i + chunk] for i in range(0, len(comp), chunk)]
    return [_comp_res(p, i == len(parts) - 1) for i, p in enumerate(parts)]


def get_pict_frames(pixels_rgba, chunk=COMP_CHUNK):
    """GET_PICT_RES (0x15) - the *uncompressed* variant. This psp2tm build never issues
    GET_PICT_CMD (only GET_COMP_PICT), so this is provided for completeness only. Same frame
    shape as GET_COMP_PICT_RES but the chunk bytes are raw RGBA rather than zlib."""
    data = bytes(pixels_rgba)
    parts = [data[i:i + chunk] for i in range(0, len(data), chunk)] or [b""]
    return [vcp_header(0x15, 0) + struct.pack("<II", 0, 1 if i == len(parts) - 1 else 0) + p
            for i, p in enumerate(parts)]


def error_res(request_payload, result=0x1b):
    """A header-only VCP error reply for a request. psp2tm surfaces the nonzero result and
    does not time out (though Razor will abort the capture on a screenshot failure).
    Default result 0x1b maps to SCE 0x8004xxxx via psp2tm's error table; use 0 only to say OK."""
    code = struct.unpack_from("<I", request_payload, 0)[0]
    return vcp_header(code | 1, result)            # RES code = CMD | 1


def screenshot_res(request_payload, width=VITA_W, height=VITA_H, pixels_rgba=None,
                   pid=0, vcount=0, chunk=COMP_CHUNK):
    """Dispatch one VCP screenshot request to the frame payload(s) to send back.
      FREEZE_CMD (0x10)        -> [FREEZE_RES]              (metadata; also for freeze-off)
      GET_COMP_PICT_CMD (0x16) -> [GET_COMP_PICT_RES, ...]  (compressed pixel chunks)
      GET_PICT_CMD (0x14)      -> [GET_PICT_RES, ...]       (raw; unused by this psp2tm)
      GET_STATUS_CMD (0x12)    -> [GET_STATUS_RES]          (minimal OK)
    `pixels_rgba` must be width*height*4 bytes A8B8G8R8 (R,G,B,A); if omitted for a picture
    request a black image is generated. Returns a list of payloads (one DECI4 frame each)."""
    code = struct.unpack_from("<I", request_payload, 0)[0]
    if code == 0x10:
        return [freeze_res(pid, vcount, width, height)]
    if code in (0x16, 0x14):
        if pixels_rgba is None:
            pixels_rgba = bytes(width * height * 4)
        if len(pixels_rgba) != width * height * 4:
            raise ValueError("pixels_rgba must be width*height*4 = %d bytes" % (width * height * 4))
        return (comp_pict_frames if code == 0x16 else get_pict_frames)(pixels_rgba, chunk)
    if code == 0x12:
        return [vcp_header(0x13, 0)]
    return None


# ---------------------------------------------------------------- self-test
# Python mirrors of psp2tm's VCP validators/consumers.

def _decode_freeze(p):                             # FUN_1400d71a0 + FUN_14008ca80
    assert struct.unpack_from("<I", p, 0)[0] == 0x11, "FREEZE_RES code"
    result = struct.unpack_from("<I", p, 4)[0]
    if result != 0:
        return None
    assert len(p) >= 0x1c, "FREEZE_RES needs result + 0x18 bytes"
    pid, vcount, w, h, fmt = struct.unpack_from("<5I", p, 8)
    return dict(pid=pid, vcount=vcount, width=w, height=h, pixel_format=fmt)


def _reassemble_comp(frames):                      # FUN_14008cc20 loop
    out, saw_last = b"", False
    for p in frames:
        assert struct.unpack_from("<I", p, 0)[0] == 0x17, "GET_COMP_PICT_RES code"
        assert len(p) >= 0x0c, "needs result+word1+last"
        result = struct.unpack_from("<I", p, 4)[0]
        assert result == 0, "chunk result 0"
        last = struct.unpack_from("<I", p, 0x0c)[0]
        out += p[0x10:]                            # chunk = rest of the frame payload
        if last != 0:
            saw_last = True
            break
    assert saw_last, "a frame must set last_flag"
    return out


if __name__ == "__main__":
    W, H = 64, 48                                  # small image so the test is quick
    # A8B8G8R8 (R,G,B,A) gradient
    px = bytearray()
    for y in range(H):
        for x in range(W):
            px += bytes([x * 4 & 0xff, y * 5 & 0xff, (x + y) & 0xff, 0xff])
    px = bytes(px)
    assert len(px) == W * H * 4

    # Razor's exact FREEZE request: 10 00 00 00 | 01 00 00 00 (view 0, freeze bit)
    req_freeze = bytes.fromhex("10000000") + struct.pack("<I", 0x00000001)
    fr = screenshot_res(req_freeze, W, H, pid=0x40010003, vcount=7)
    assert len(fr) == 1
    meta = _decode_freeze(fr[0])
    assert meta == dict(pid=0x40010003, vcount=7, width=W, height=H, pixel_format=0)
    print("FREEZE_RES: %s -> %s" % (fr[0].hex(" "), meta))

    # GET_COMP_PICT: 16 00 00 00 (no body)
    req_comp = bytes.fromhex("16000000")
    frames = screenshot_res(req_comp, W, H, pixels_rgba=px, chunk=1024)
    comp = _reassemble_comp(frames)
    back = zlib.decompress(comp)                    # TMAPI FUN_180099f50 inflate
    assert back == px and len(back) == W * H * 4
    print("GET_COMP_PICT_RES: %d frame(s), %d compressed bytes -> %d px bytes OK"
          % (len(frames), len(comp), len(back)))

    # a real 960x544 image fragments into a handful of frames
    big = bytes(VITA_W * VITA_H * 4)                # black; compresses tiny but exercises sizing
    frames = comp_pict_frames(bytes(0x30000) + b"\x01" * 0x20000)   # ~forces multiple chunks
    assert len(frames) >= 1 and struct.unpack_from("<I", frames[-1], 0x0c)[0] != 0
    assert all(len(f) <= 0x10 + COMP_CHUNK for f in frames)
    _reassemble_comp(frames)

    # header-only error is accepted by psp2tm's decoder (result != 0 short-circuits)
    err = error_res(req_freeze, 0x1b)
    assert err == bytes.fromhex("11000000") + struct.pack("<I", 0x1b) and _decode_freeze(err) is None

    # freeze-off (arg 0) also returns metadata
    assert screenshot_res(bytes.fromhex("1000000000000000"), W, H)[0][:4] == bytes.fromhex("11000000")
    print("VCP self-test OK")
