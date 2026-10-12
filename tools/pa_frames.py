"""Pack Performance Analysis (PA) trace events into the raw buffer format Razor reads.

Format (RAZOR_PA_TRACE_FORMAT.md, from PSP2Razor.dll FUN_10217d50 / FUN_10219450):
  buffer = N * 0x80-byte frames
  frame  = u16 (unused) | 7 * u16 slot descriptor | 7 * 16-byte slot
  slot type = (desc >> 8) & 0x7f  (desc & 0x8000 clear)
    0x7c  one 64-bit bookmark      (bytes 0..7)
    0x7d  two 64-bit bookmarks     (bytes 0..15)
    0x7e  u32 time low 32, u16 time high 16, u16 0, then one 64-bit bookmark
    0x10  16 bytes of PFT (ARM program flow trace) for source desc & 0xff
  64-bit bookmark: w0 = fifo<<31 | regno<<27 | master<<21 | (time & 0x1fffff), w1 = data
  A 64-bit bookmark's time is its 21 bits | the upper bits of the last 0x7e slot, so a 0x7e
  slot must precede any bookmark whose time >> 21 differs from the running base.
Timebase: 333 MHz ticks, 48 bits.
"""
import struct

TIMEBASE_HZ = 333_000_000
FRAME_SIZE = 0x80
SLOTS_PER_FRAME = 7

FIFO_A, FIFO_B = 0, 1

SLOT_PFT = 0x10
SLOT_BM64X1 = 0x7C
SLOT_BM64X2 = 0x7D
SLOT_BM_TS = 0x7E


def ticks(seconds):
    return int(round(seconds * TIMEBASE_HZ))


def bookmark_words(fifo, regno, master, time48, data):
    w0 = ((fifo & 1) << 31) | ((regno & 0xF) << 27) | ((master & 0x3F) << 21) | (time48 & 0x1FFFFF)
    return struct.pack("<II", w0, data & 0xFFFFFFFF)


class Bookmark:
    """One bookmark event: (fifo, regno, master, time48, data)."""
    __slots__ = ("fifo", "regno", "master", "time", "data")

    def __init__(self, fifo, regno, master, time, data):
        self.fifo, self.regno, self.master, self.time, self.data = fifo, regno, master, time, data


class PftChunk:
    """16 bytes of PFT for a trace source (CPU), placed at `time` in the stream order."""
    __slots__ = ("source", "time", "payload")

    def __init__(self, source, time, payload):
        assert len(payload) == 16
        self.source, self.time, self.payload = source, time, payload


def pack(events, pad_frame=True):
    """events: iterable of Bookmark / PftChunk (and raw (desc, 16 bytes) tuples for
    slots produced elsewhere, placed in the given order). Bookmarks are emitted in time
    order; the relative order of equal-time events is preserved. Returns bytes."""
    evs = list(events)
    keyed = sorted(enumerate(evs), key=lambda ie: (getattr(ie[1], "time", 0), ie[0]))
    slots = []
    base = None                                     # time >> 21 of the last 0x7e slot
    pending = None                                  # one 64-bit bookmark waiting for a pair

    def flush_pending():
        nonlocal pending
        if pending is not None:
            slots.append((SLOT_BM64X1 << 8, pending + bytes(8)))
            pending = None

    for _, e in keyed:
        if isinstance(e, Bookmark):
            words = bookmark_words(e.fifo, e.regno, e.master, e.time, e.data)
            if base is None or (e.time >> 21) != base:
                flush_pending()
                base = e.time >> 21
                t = e.time & 0xFFFFFFFFFFFF
                slots.append((SLOT_BM_TS << 8, struct.pack("<IHH", t & 0xFFFFFFFF, t >> 32, 0) + words))
            elif pending is None:
                pending = words
            else:
                slots.append((SLOT_BM64X2 << 8, pending + words))
                pending = None
        elif isinstance(e, PftChunk):
            flush_pending()
            slots.append(((SLOT_PFT << 8) | (e.source & 0xFF), e.payload))
        else:
            flush_pending()
            desc, payload = e
            assert len(payload) == 16
            slots.append((desc, payload))
    flush_pending()

    out = bytearray()
    for i in range(0, len(slots), SLOTS_PER_FRAME):
        chunk = slots[i:i + SLOTS_PER_FRAME]
        if len(chunk) < SLOTS_PER_FRAME and not pad_frame:
            break
        descs = [d for d, _ in chunk] + [0] * (SLOTS_PER_FRAME - len(chunk))
        body = b"".join(p for _, p in chunk) + bytes(16 * (SLOTS_PER_FRAME - len(chunk)))
        out += struct.pack("<H7H", 0, *descs) + body
    return bytes(out)


def iter_bookmarks(buf):
    """Decoder mirroring FUN_10217d50, for self-checks: yields (fifo, regno, master, time48, data)."""
    base_lo = base_hi = None
    for f in range(0, len(buf) - FRAME_SIZE + 1, FRAME_SIZE):
        descs = struct.unpack_from("<7H", buf, f + 2)
        for i, d in enumerate(descs):
            if d & 0x8000:
                continue
            t = (d >> 8) & 0x7F
            s = f + 0x10 + i * 0x10
            words = []
            if t == SLOT_BM64X1:
                words = [s]
            elif t == SLOT_BM64X2:
                words = [s, s + 8]
            elif t == SLOT_BM_TS:
                lo, hi = struct.unpack_from("<IH", buf, s)
                base_lo, base_hi = lo & 0xFFE00000, hi
                words = [s + 8]
            for w in words:
                w0, w1 = struct.unpack_from("<II", buf, w)
                if base_lo is None:
                    continue
                time = (base_hi << 32) | base_lo | (w0 & 0x1FFFFF)
                yield ((w0 >> 31) & 1, (w0 >> 27) & 0xF, (w0 >> 21) & 0x3F, time, w1)


if __name__ == "__main__":
    evs = [Bookmark(FIFO_B, 6, 1, ticks(0.001) + i * 12345, 0x1000 + i) for i in range(40)]
    evs += [Bookmark(FIFO_A, 9, 2, ticks(0.0015) + i * 3_000_000, 0x2000 + i) for i in range(10)]
    raw = pack(evs)
    got = list(iter_bookmarks(raw))
    want = sorted(((e.fifo, e.regno, e.master, e.time, e.data) for e in evs), key=lambda x: x[3])
    assert got == want, (got[:5], want[:5])
    print("pa_frames self-test ok: %d events -> %d frames" % (len(evs), len(raw) // FRAME_SIZE))
