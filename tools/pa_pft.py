"""Synthesize the ARM program-flow-trace (PFT) slots of a Razor PA trace buffer from software
PC samples, for Razor's "PC sampling" CPU capture (CreateArmTrace sampleMode 6).

See ../docs/RAZOR_PFT_SAMPLE_FORMAT.md for the derivation (PSP2Razor.dll 3.60 addresses).

Input sample : (cpu, time48, pc, thumb, context_id)
Output slot  : (desc_u16, 16 bytes)  -- one 0x80-byte PA frame holds 7 slots; packing is done elsewhere.

What Razor does with it (sampleMode 6, FUN_10219450 -> FUN_103eb660 -> FUN_103ec9b0):
  * every type-0x10 slot is exactly one 16-byte CoreSight formatter frame (FUN_103edc00/FUN_103edd70);
    formatter trace ID 1..4 = CPU 0..3 byte stream;
  * each CPU stream must start with A-sync (00 00 00 00 00 80);
  * every I-sync packet (0x08) whose reason is 1 ("Trace On") adds 1 to a global
    map<address, count> (FUN_103ee8f0 -> FUN_103f4870); time, cpu, thumb, context ID are dropped;
  * any header byte Razor does not know (e.g. VMID 0x3C) aborts the whole PFT decode.

Ordering constraints for whoever packs frames:
  * keep the returned slots in order (slot 0..6 within a frame, frames in buffer order);
  * any other slot type (bookmarks 0x7c-0x7f, unused desc 0x0000) may be interleaved freely;
  * never emit an overflow slot (desc 0x9000|x): it starts a new trace segment and every CPU stream
    would need a new A-sync (use PftSlotEncoder.resync() if you really have to);
  * the buffer as a whole needs at least one 0x7e bookmark-timestamp slot, otherwise
    ProcessMainTraceBuffer(0/1) fails before the PFT pass runs (FUN_1021cdb0 -> FUN_102185a0).
"""
import struct

# CreateArmTrace traceMode bits consumed by the decoder (it is the PTM control-register layout)
TM_CYCLE_ACCURATE = 0x00001000     # I-sync (reason != 0) / branch / atom / timestamp carry a cycle count
TM_CTXID_MASK = 0x0000C000         # 0: none, 0x4000: 1 byte, 0x8000: 2 bytes, 0xC000: 4 bytes
TM_TIMESTAMP = 0x10000000          # not read by the decoder itself

# What CPSP2Target sets (FUN_10199430) from capture option +0x20:
PC_SAMPLING = dict(trace_mode=0x00000000, sample_mode=6, ts_period=0, sample_period=1000)
PROGRAM_FLOW = dict(trace_mode=0x10001000, sample_mode=5, ts_period=0xFFFF, sample_period=0)

SLOT_TYPE_ARM_TRACE = 0x10
A_SYNC = b"\x00\x00\x00\x00\x00\x80"
IGNORE = 0x66                      # 1-byte PFT Ignore packet, used as padding
ISYNC_HEADER = 0x08
REASON_PERIODIC, REASON_TRACE_ON, REASON_OVERFLOW, REASON_DEBUG = 0, 1, 2, 3
DATA_PER_FRAME = 14                # 16 - ID byte - aux byte


def ctxid_size(trace_mode):
    return (0, 1, 2, 4)[(trace_mode & TM_CTXID_MASK) >> 14]


def encode_cycle_count(count):
    """Cycle count as parsed by FUN_103ee460: byte0 bits5:2 = c[3:0], bit6 = more;
    bytes 1..3: 7 bits, bit7 = more; byte 4: c[31:25]."""
    count &= 0xFFFFFFFF
    first = (count & 0xF) << 2
    rest = count >> 4
    out = bytearray([first | (0x40 if rest else 0)])
    while rest:
        if len(out) == 4:
            out.append(rest & 0x7F)
            break
        b = rest & 0x7F
        rest >>= 7
        out.append(b | (0x80 if rest else 0))
    return bytes(out)


def isync_packet(pc, thumb, context_id=0, trace_mode=0, reason=REASON_TRACE_ON, ns=1, cycle_count=1):
    """I-sync as parsed by FUN_103ebd30: 08 | addr LE (bit0 = Thumb) | info | [cycle] | [ctxid]."""
    addr = (pc & 0xFFFFFFFE) | (1 if thumb else 0)
    info = 0x80 | ((reason & 3) << 5) | ((ns & 1) << 3)     # Razor reads bits 6:5, 3, 2 only
    pkt = bytearray([ISYNC_HEADER]) + struct.pack("<I", addr) + bytes([info])
    if reason != REASON_PERIODIC and trace_mode & TM_CYCLE_ACCURATE:
        pkt += encode_cycle_count(cycle_count)
    n = ctxid_size(trace_mode)
    if n:
        pkt += struct.pack("<I", context_id & 0xFFFFFFFF)[:n]
    return bytes(pkt)


def formatter_frame(trace_id, data):
    """One CoreSight formatter frame carrying <= 14 bytes of a single source (FUN_103edd70):
    byte0 = ID byte (aux bit0 = 0: effective immediately), bytes 1..14 data, byte15 = aux bits.
    Even-position data bytes keep bit0 in the aux byte."""
    assert 1 <= trace_id <= 4 and len(data) <= DATA_PER_FRAME
    data = bytes(data) + bytes([IGNORE]) * (DATA_PER_FRAME - len(data))
    frame = bytearray(16)
    frame[0] = (trace_id << 1) | 1
    aux = 0
    for i, d in enumerate(data):
        pos = i + 1
        if pos & 1:
            frame[pos] = d
        else:
            frame[pos] = d & 0xFE
            aux |= (d & 1) << (pos >> 1)
    frame[15] = aux
    return bytes(frame)


def arm_desc(channel):
    return (SLOT_TYPE_ARM_TRACE << 8) | (channel & 0xFF)   # low byte only printed by Razor


class PftSlotEncoder:
    """Streaming encoder. add_sample() returns (time48, desc, slot) tuples that are complete;
    flush() pads the pending bytes of every CPU with Ignore packets and returns their slots.
    time48 of a slot = time of the newest sample whose bytes ended in (or before) that slot,
    for interleaving with bookmark slots; Razor's sampleMode-6 decode does not use it."""

    def __init__(self, trace_mode=0, ns=1, cycle_count=1):
        self.trace_mode, self.ns, self.cycle_count = trace_mode, ns, cycle_count
        self.pending = {}
        self.synced = set()
        self.last_time = {}

    def resync(self):
        """Force a new A-sync on every CPU (only needed after an overflow slot)."""
        self.synced.clear()

    def _emit_full(self, cpu):
        out = []
        buf = self.pending[cpu]
        while len(buf) >= DATA_PER_FRAME:
            out.append((self.last_time[cpu], arm_desc(cpu), formatter_frame(cpu + 1, buf[:DATA_PER_FRAME])))
            del buf[:DATA_PER_FRAME]
        return out

    def add_sample(self, cpu, time48, pc, thumb, context_id=0):
        if not 0 <= cpu <= 3:
            raise ValueError("cpu must be 0..3 (formatter IDs 1..4)")
        buf = self.pending.setdefault(cpu, bytearray())
        if cpu not in self.synced:
            buf += A_SYNC
            self.synced.add(cpu)
        buf += isync_packet(pc, thumb, context_id, self.trace_mode, REASON_TRACE_ON, self.ns, self.cycle_count)
        self.last_time[cpu] = time48
        return self._emit_full(cpu)

    def flush(self):
        out = []
        for cpu in sorted(self.pending):
            buf = self.pending[cpu]
            if buf:
                out.append((self.last_time[cpu], arm_desc(cpu), formatter_frame(cpu + 1, buf)))
                buf.clear()
        return out


def samples_to_timed_slots(samples, trace_mode=0, ns=1, cycle_count=1, flush=True):
    enc = PftSlotEncoder(trace_mode, ns, cycle_count)
    out = []
    for s in sorted(samples, key=lambda s: s[1]):
        out += enc.add_sample(*s)
    if flush:
        out += enc.flush()
    return out


def samples_to_slots(samples, trace_mode=0, ns=1, cycle_count=1):
    """[(cpu, time48, pc, thumb, context_id)] -> [(desc_u16, 16-byte bytes)] in buffer order."""
    return [(d, b) for _, d, b in samples_to_timed_slots(samples, trace_mode, ns, cycle_count)]


# ----------------------------------------------------------------------------------------------
# Reference decoder: re-implements the Razor code paths used for sampleMode 6, for self-testing.
def razor_deformat(slots):
    """FUN_10219450/FUN_103edc00/FUN_103edd70: type-0x10 slots -> {cpu: bytearray}."""
    streams = {c: bytearray() for c in range(4)}
    acc, cur, pend = bytearray(), 0x70, 0x70
    for desc, slot in slots:
        if desc & 0x8000 or (desc >> 8) & 0x7F != SLOT_TYPE_ARM_TRACE:
            continue
        i = 0
        while i < 16:
            if slot[i:i + 4] == b"\xff\xff\xff\x7f":
                raise ValueError("FSYNC in slot (would reset/misalign the formatter)")
            acc.append(slot[i])
            if len(acc) == 16:
                aux = acc[15]
                for j in range(16):
                    b = acc[j]
                    if j & 1 == 0:
                        if b & 1 == 0:
                            if 1 <= cur <= 4:
                                streams[cur - 1].append(((aux >> (j >> 1)) ^ b) & 1 ^ b)
                        elif j == 14 or (aux >> (j >> 1)) & 1 == 0:
                            cur = b >> 1
                        else:
                            pend = b >> 1
                    else:
                        if j != 15 and 1 <= cur <= 4:
                            streams[cur - 1].append(b)
                        if pend != 0x70:
                            cur, pend = pend, 0x70
                acc.clear()
            i += 1
    return streams


def razor_decode_pc_samples(stream, trace_mode=0, hist=None):
    """FUN_103ec9b0 with mode flag 0 (decode_arm_trace): returns map address -> count."""
    hist = {} if hist is None else hist
    n = len(stream)

    def find_async(off):
        zeros = 0
        while off < n:
            if stream[off] == 0:
                zeros += 1
            elif stream[off] == 0x80 and zeros > 4:
                return off + 1
            else:
                zeros = 0
            off += 1
        return None

    def cycle(off):                       # FUN_103ee460, returns offset of its last byte
        if off >= n:
            return None
        if stream[off] & 0x40:
            for k in range(4):
                off += 1
                if off >= n:
                    return None
                if k == 3 or not stream[off] & 0x80:
                    break
        return off

    off = find_async(0) if n else None
    while off is not None and off < n:
        h = stream[off]
        if h in (0x0C, 0x66, 0x76):
            off += 1
        elif h == 0x00:
            off = find_async(off)
        elif h & 1:
            raise NotImplementedError("branch packet: not produced by this encoder")
        elif h == ISYNC_HEADER:
            if n <= off + 5:
                break
            addr = struct.unpack_from("<I", stream, off + 1)[0] & 0xFFFFFFFE
            reason = (stream[off + 5] >> 5) & 3
            off += 5
            if reason and trace_mode & TM_CYCLE_ACCURATE:
                off = cycle(off + 1)
                if off is None:
                    break
            if ctxid_size(trace_mode):
                off += ctxid_size(trace_mode)
                if off > n:
                    break
            off += 1
            if reason == REASON_TRACE_ON:
                hist[addr] = hist.get(addr, 0) + 1
        else:
            raise ValueError("unknown PFT header 0x%02x at %d: Razor aborts the decode" % (h, off))
    return hist


def pack_frames(slots, header=0):
    """Test helper only: 7 slots per 0x80-byte frame, unused slots desc 0x0000 (type 0, skipped)."""
    out = bytearray()
    for i in range(0, len(slots), 7):
        chunk = slots[i:i + 7]
        descs = [d for d, _ in chunk] + [0] * (7 - len(chunk))
        body = b"".join(b for _, b in chunk) + bytes(16 * (7 - len(chunk)))
        out += struct.pack("<H7H", header, *descs) + body
    return bytes(out)


def _selftest():
    ex = [(0, 0x000100000000, 0x81000100, 0, 0),
          (0, 0x000100002000, 0x81000235, 1, 0),
          (0, 0x000100004000, 0x8100A000, 0, 0)]
    slots = samples_to_slots(ex)
    for d, b in slots:
        print("desc=0x%04x  %s" % (d, b.hex(" ")))
    streams = razor_deformat(slots)
    print("cpu0 stream:", streams[0].hex(" "))
    hist = razor_decode_pc_samples(streams[0])
    print("histogram:", {hex(k): v for k, v in hist.items()})
    assert hist == {0x81000100: 1, 0x81000234: 1, 0x8100A000: 1}

    import random
    rnd = random.Random(1)
    for tm in (0, 0x1000, 0x4000, 0x8000, 0xC000, 0x1000C000):
        samples = [(rnd.randrange(4), t, rnd.getrandbits(32), rnd.getrandbits(1), rnd.getrandbits(32))
                   for t in range(3000)]
        slots = samples_to_slots(samples, trace_mode=tm, cycle_count=rnd.randrange(1, 1 << 20))
        streams = razor_deformat(slots)
        hist = {}
        for c in range(4):
            razor_decode_pc_samples(streams[c], tm, hist)
        want = {}
        for s in samples:
            k = s[2] & 0xFFFFFFFE
            want[k] = want.get(k, 0) + 1
        assert hist == want, "trace_mode 0x%x mismatch" % tm
        assert len(pack_frames(slots)) % 0x80 == 0
    print("self-test OK")


if __name__ == "__main__":
    _selftest()
