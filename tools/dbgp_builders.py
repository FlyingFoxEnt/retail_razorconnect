"""DBGP (DECI4 protocol 0x20000) response payload builders for the MODULE (0x40)
and THREAD (0x30) groups, as decoded by psp2tm.exe.

Every function returns the DBGP *payload* (what goes after the 16-byte DECI4
frame header). Wrap it with the mock's frame(payload, node, DBGP, flags).
Layouts and the psp2tm functions that prove them: ../docs/DBGP_MODULE_THREAD_FORMAT.md

Common response header (12 bytes, FUN_1400d1c80 + per-message validators):
    +0x00 u8  b0 (echo of request byte 0, not checked)
    +0x01 u8  group            checked == request group
    +0x02 u8  code             checked == request code + 1 (RES)
    +0x03 u8  0
    +0x04 u16 seq              first frame MUST be 0 (else 0x100018)
    +0x06 u8  frag flags       bit0 = more fragments follow
    +0x07 u8  0
    +0x08 u32 result           0 = OK; nonzero is returned to the caller as-is
                               (e.g. 8 -> "unsupported", makes THREAD_INFO_EX
                               fall back to THREAD_INFO)

Requests seen from psp2tm (u32 hdr = b0 | group<<8 | code<<16, then args):
    MODULE GET_MOD_INFO     00 40 00 00 | u32 pid            -> RES code 0x01
    MODULE GET_META_DATA    00 40 02 00 | u32 pid | u32 modid -> RES code 0x03
    MODULE GET_LIB_INFO     00 40 10 00 | u32 pid            -> RES code 0x11
    THREAD GET_THREAD_INFO  00 30 00 00 | u32 pid            -> RES code 0x01
    THREAD GET_THREAD_INFO_EX 00 30 02 00 | u32 pid          -> RES code 0x03
    THREAD GET_THREAD_NAMES 00 30 14 00 | u32 pid            -> RES code 0x15
    PROCESS GET_PROCESS_INFO    00 20 00 00                  -> 0x01
    PROCESS ATTACH_PROCESS      00 20 10 00 | pid | flags    -> 0x11 (header only)
    PROCESS DETACH_PROCESS      00 20 12 00 | pid | resume   -> 0x13 (header only)
    PROCESS SUSPEND_PROCESS     00 20 20 00 | pid            -> 0x21
    PROCESS RESUME_PROCESS      00 20 22 00 | pid | n | n*tid -> 0x23
    PROCESS SUSPEND_APPLICATION 00 20 24 00 | pid            -> 0x25
    PROCESS RESUME_APPLICATION  00 20 26 00 | pid            -> 0x27
    PROCESS ALLOC_EXEC_PAGE     00 20 30 00 | pid | size     -> 0x31
    PROCESS ALLOC_DATA_PAGE     00 20 32 00 | pid | size     -> 0x33
    PROCESS GET_MEMBLK_INFO     00 20 40 00 | pid            -> 0x41
    SYSTEM  GET_CONF            00 10 00 00                  -> 0x01
    SYSTEM  RDMEM               00 10 10 00 | pid | addr | size          -> 0x11
    SYSTEM  WRMEM               00 10 12 00 | pid | addr | len | data    -> 0x13
    THREAD  SUSPEND_THREAD      00 30 10 00 | pid | tid                  -> 0x11
    THREAD  RESUME_THREAD       00 30 12 00 | pid | tid                  -> 0x13
    THREAD  GET_STACK_INFO      00 30 16 00 | pid                        -> 0x17
    THREAD  GET_SYNC_INFO       00 30 20 00 | pid | nT | nT*u32 | nID | nID*u32 -> 0x21
    THREAD  GET_APP_OBJECT_INFO 00 30 30 00 | pid                        -> 0x31
    THREAD  GET_FIBER_STACK_INFO 00 30 32 00 | pid                       -> 0x33
Target-pushed SYSTEM notifications (group 0x10, codes 0xc0..0xd5): *_notification().
"""
import struct

__all__ = [
    "dbgp_header", "error_res", "fragment",
    "module_entry", "module_list_res", "lib_entry", "lib_info_res", "meta_data_res",
    "thread_entry", "thread_info_res", "thread_info_ex_res", "thread_names_res",
    "process_entry", "process_info_res", "attach_process_res", "detach_process_res",
    "suspend_process_res", "resume_process_res", "app_suspend_res", "app_resume_res",
    "alloc_page_res", "memblk_entry", "memblk_info_res",
    "get_conf_res", "rdmem_res", "wrmem_res",
    "stop_notification", "thread_create_notification", "thread_exit_notification",
    "process_create_notification", "process_exit_notification",
    "process_kill_notification", "prx_unload_notification",
    "app_suspended_notification", "app_resumed_notification",
    "sync_info_res", "sync_semaphore", "sync_event", "sync_mutex", "sync_lwmutex",
    "sync_record", "suspend_thread_res", "resume_thread_res",
    "stack_info_res", "app_object_info_res", "fiber_stack_info_res",
    "SYNC_TYPES",
    "build_reply",
]

# eModuleTypes / eModuleStatus / eThreadStatus (Interop.PSP2TMAPILib)
MODULE_TYPE_FIXED_ELF, MODULE_TYPE_PRX = 0x10, 0x20
MODULE_STATUS_LOADED, MODULE_STATUS_STARTING, MODULE_STATUS_LIVE = 0, 1, 2
MODULE_STATUS_STOPPING, MODULE_STATUS_STOPPED = 3, 4
THREAD_STATUS_RUNNING, THREAD_STATUS_READY, THREAD_STATUS_STANDBY = 1, 2, 4
THREAD_STATUS_WAITING, THREAD_STATUS_DORMANT = 8, 0x10

STOP_REASON_SIZE = 0x14          # size word of the embedded StopReason block
DBGP_RESULT_UNSUPPORTED = 8      # FUN_140112230 falls back to GET_THREAD_INFO on this


def _pad4(b):
    return b + bytes((-len(b)) % 4)


def _fixed_str(s, slot, maxlen):
    """UTF-8, truncated to maxlen bytes, NUL-terminated, zero-padded to slot."""
    b = s.encode("utf-8") if isinstance(s, str) else bytes(s)
    return (b[:maxlen] + b"\0").ljust(slot, b"\0")[:slot]


def _seq(seq_bytes):
    if seq_bytes is None:
        return b"\0\0\0\0"
    if isinstance(seq_bytes, int):
        return struct.pack("<I", seq_bytes)
    seq_bytes = bytes(seq_bytes)
    if len(seq_bytes) != 4:
        raise ValueError("seq_bytes must be 4 bytes (u16 seq, u8 frag, u8 rsv)")
    return seq_bytes


def dbgp_header(b0, group, code, seq_bytes=None, result=0):
    """12-byte response header. `code` may be the request code (even) or the
    response code (odd); the RES code is always code | 1."""
    return struct.pack("<BBBB", b0 & 0xFF, group & 0xFF, (code | 1) & 0xFF, 0) + \
        _seq(seq_bytes) + struct.pack("<I", result & 0xFFFFFFFF)


def error_res(b0, group, code, seq_bytes=None, result=DBGP_RESULT_UNSUPPORTED):
    """A header-only response with a nonzero result. psp2tm's FUN_14008f540 returns
    `result` to the caller before any validator runs, so no body is needed."""
    return dbgp_header(b0, group, code, seq_bytes, result)


def fragment(payload, max_frame=0x10000):
    """Split one logical DBGP response payload into several frame payloads
    (FUN_14008f540 reassembly rules). Frame 0 = header + first data chunk, seq 0.
    Frames 1..n repeat the 12-byte header with seq 1,2,.. and result 0; their
    bytes after the header are appended raw (split may fall anywhere). bit0 of
    +0x06 is set on every frame except the last. Returns a list of payloads;
    each must be wrapped in its own 16-byte DECI4 frame."""
    max_pay = max_frame - 16
    if max_pay <= 12:
        raise ValueError("max_frame too small")
    if len(payload) <= max_pay:
        p = bytearray(payload)
        p[6] &= 0xFE
        return [bytes(p)]
    hdr = bytearray(payload[:12])
    data = payload[12:]
    step = max_pay - 12
    chunks = [data[i:i + step] for i in range(0, len(data), step)]
    out = []
    for i, ch in enumerate(chunks):
        h = bytearray(hdr)
        struct.pack_into("<H", h, 4, i)
        h[6] = (h[6] & 0xFE) | (1 if i < len(chunks) - 1 else 0)
        h[7] = 0
        struct.pack_into("<I", h, 8, 0)
        out.append(bytes(h) + ch)
    return out


# ---------------------------------------------------------------- MODULE group

def module_entry(m):
    """One GET_MOD_INFO_RES entry (decoder FUN_1400f6570). Keys (all optional
    except name): id, guid, sdk_version, module_version (u16), type (u8),
    flags (u16), start_entry, ref_count, stop_entry, exit_entry, name,
    status, segments=[{attr, base, size, align}], exidx_start, exidx_end,
    extab_start, extab_end, tail (bool, default True)."""
    g = m.get
    segs = g("segments", [])
    body = struct.pack("<IIHHBBHIIII",
                       g("id", 0), g("sdk_version", 0),
                       g("module_version", 0) & 0xFFFF, 0,
                       g("type", MODULE_TYPE_PRX) & 0xFF, 0,
                       g("flags", 0) & 0xFFFF,
                       g("start_entry", 0), g("ref_count", 1),
                       g("stop_entry", 0), g("exit_entry", 0))
    body += _fixed_str(g("name", ""), 32, 26)          # +0x24, host reads 26 bytes
    body += struct.pack("<III", g("status", MODULE_STATUS_LIVE), g("guid", 0), len(segs))
    for s in segs:                                     # +0x50, 0x14 each
        body += struct.pack("<5I", 0x14, s.get("attr", 0), s.get("base", 0),
                            s.get("size", 0), s.get("align", 0))
    if g("tail", True):
        body += struct.pack("<4I", g("exidx_start", 0), g("exidx_end", 0),
                            g("extab_start", 0), g("extab_end", 0))
    return struct.pack("<I", 4 + len(body)) + body


def module_list_res(b0, group, code, seq_bytes, modules, pid):
    """DBGP_MODULE_GET_MOD_INFO_RES (0x40/0x01) for request 00 40 00 00 | pid.
    Validator FUN_1400d06f0: result 0, pid echoed (FUN_140084760 compares it to the
    request, else 0x100010 -> 0x8004028b), entries walk in-bounds, entry[0].size>=0x50."""
    return dbgp_header(b0, group, code, seq_bytes) + \
        struct.pack("<II", pid, len(modules)) + b"".join(module_entry(m) for m in modules)


def lib_entry(lib):
    """One GET_LIB_INFO_RES entry (decoder FUN_1400f5e60 + FUN_14010b680). Keys:
    id, module_id, attr, ref_count, name, functions=[(nid, addr)],
    variables=[(nid, addr)], tls_offsets=[u32], client_module_ids=[u32]."""
    g = lib.get
    fns, vars_ = g("functions", []), g("variables", [])
    tls, cli = g("tls_offsets", []), g("client_module_ids", [])
    body = struct.pack("<8I", g("id", 0), g("module_id", 0), g("attr", 0), g("ref_count", 1),
                       len(fns), len(vars_), len(tls), len(cli))
    body += b"".join(struct.pack("<II", nid, addr) for nid, addr in fns)
    body += b"".join(struct.pack("<II", nid, addr) for nid, addr in vars_)
    body += b"".join(struct.pack("<I", x) for x in tls)
    body += b"".join(struct.pack("<I", x) for x in cli)
    nb = g("name", "")
    nb = (nb.encode("utf-8") if isinstance(nb, str) else bytes(nb))
    if nb:
        nb += b"\0"
        body += struct.pack("<I", len(nb)) + _pad4(nb)
    else:
        body += struct.pack("<I", 0)
    return struct.pack("<I", 4 + len(body)) + body


def lib_info_res(b0, group, code, seq_bytes, libs, pid):
    """DBGP_MODULE_GET_LIB_INFO_RES (0x40/0x11) for request 00 40 10 00 | pid.
    Validator FUN_1400d05b0: pid echoed, entry walk, entry[0].size >= 0x24."""
    return dbgp_header(b0, group, code, seq_bytes) + \
        struct.pack("<II", pid, len(libs)) + b"".join(lib_entry(x) for x in libs)


def meta_data_res(b0, group, code, seq_bytes, pid, module_id, data):
    """DBGP_MODULE_GET_META_DATA_RES (0x40/0x03) for request 00 40 02 00 | pid | modid.
    Validator FUN_1400d0660; FUN_140084670 checks pid (0x100010) and modid (0x100014)."""
    data = bytes(data)
    return dbgp_header(b0, group, code, seq_bytes) + \
        struct.pack("<III", pid, module_id, len(data)) + _pad4(data)


# ---------------------------------------------------------------- THREAD group

THREAD_BASIC_SIZE, THREAD_EX_SIZE = 0xAC, 0xD0


def thread_entry(t, ex=False):
    """One thread record. Basic = 0xAC bytes (decoder FUN_1400f7020), EX = 0xD0
    bytes (FUN_1400f6e90, adds 9 u32 WaitDetails at +0xAC). Keys: id, name,
    init_attr, attr, status, entry, stack_top, stack_size, unk_40, arg_size,
    arg_block, init_priority, priority, init_affinity, affinity, last_cpu,
    wait_type, wait_target, clock_run (u64), stop_code, stop_code_id, stop_attr,
    exit_status, int_preempt, thread_preempt, release_count, change_cpu_count,
    vfp_mode, pc, wait_timeout, wait_detail (u64), wait_details (<=9 u32, EX)."""
    g = t.get
    body = struct.pack("<I", g("id", 0))                                  # +0x04
    body += _fixed_str(g("name", ""), 32, 31)                             # +0x08
    body += struct.pack("<7I", g("init_attr", 0), g("attr", 0),           # +0x28
                        g("status", THREAD_STATUS_READY), g("entry", 0),
                        g("stack_top", 0), g("stack_size", 0), g("unk_40", 0))
    body += struct.pack("<9I", g("arg_size", 0), g("arg_block", 0),       # +0x44
                        g("init_priority", 0x10000100), g("priority", 0x10000100),
                        g("init_affinity", 0), g("affinity", 0), g("last_cpu", 0),
                        g("wait_type", 0), g("wait_target", 0))
    body += struct.pack("<Q", g("clock_run", 0))                          # +0x68
    body += struct.pack("<5I", STOP_REASON_SIZE, g("stop_code", 0),       # +0x70
                        g("stop_code_id", 0), 0, g("stop_attr", 0))
    body += struct.pack("<8I", g("exit_status", 0), g("int_preempt", 0),  # +0x84
                        g("thread_preempt", 0), g("release_count", 0),
                        g("change_cpu_count", 0), g("vfp_mode", 0), g("pc", 0),
                        g("wait_timeout", 0))
    body += struct.pack("<Q", g("wait_detail", 0))                        # +0xa4
    if ex:
        wd = list(g("wait_details", []))[:9]
        body += struct.pack("<9I", *(wd + [0] * (9 - len(wd))))           # +0xac
    rec = struct.pack("<I", 4 + len(body)) + body
    assert len(rec) == (THREAD_EX_SIZE if ex else THREAD_BASIC_SIZE)
    return rec


def thread_info_res(b0, group, code, seq_bytes, threads, pid):
    """DBGP_THREAD_GET_THREAD_INFO_RES (0x30/0x01) for request 00 30 00 00 | pid.
    Validator FUN_1400d0e40 (pid echoed, entry walk; no min size)."""
    return dbgp_header(b0, group, code, seq_bytes) + \
        struct.pack("<II", pid, len(threads)) + b"".join(thread_entry(t) for t in threads)


def thread_info_ex_res(b0, group, code, seq_bytes, threads, pid):
    """DBGP_THREAD_GET_THREAD_INFO_EX_RES (0x30/0x03) for request 00 30 02 00 | pid.
    This is what the thread-list handler FUN_140112230 asks FIRST.
    Validator FUN_1400d0da0 (pid echoed, entry walk)."""
    return dbgp_header(b0, group, code, seq_bytes) + \
        struct.pack("<II", pid, len(threads)) + b"".join(thread_entry(t, ex=True) for t in threads)


def thread_names_res(b0, group, code, seq_bytes, threads):
    """DBGP_THREAD_GET_THREAD_NAMES_RES (0x30/0x15) for request 00 30 14 00 | pid.
    Validator FUN_1400d0ee0: NO pid echo; count at +0x0c; fixed 0x24-byte records
    (u32 id, char[32] NUL-terminated name) consumed by FUN_140111f50."""
    return dbgp_header(b0, group, code, seq_bytes) + struct.pack("<I", len(threads)) + \
        b"".join(struct.pack("<I", t.get("id", 0)) + _fixed_str(t.get("name", ""), 32, 31)
                 for t in threads)


# ---------------------------------------------------------------- PROCESS group (0x20)

# eProcessAttr (mock_pamp.py): LOADED 1, DEBUG_STATE 2, SYSTEM 4, SUSPENDED 8,
# DEBUGGABLE 0x10000, ATTACHED 0x20000
PROC_ATTR_SUSPENDED, PROC_ATTR_DEBUGGABLE, PROC_ATTR_ATTACHED = 8, 0x10000, 0x20000
# target result codes psp2tm treats specially
RESULT_ATTACH_OK_ALT = 0x20052      # FUN_1400f9090: ATTACH result 0x20052 == success
RESULT_SUSPEND_ALREADY = 0x20056    # FUN_140140270: success, "already stopped", no data
RESULT_SUSPEND_RETRY = 0x20058      # FUN_140140270: psp2tm retries SUSPEND once


def process_entry(p):
    """One ProcessInfo wire entry (decoder FUN_1400f66f0; see DBGP_PROCINFO_FORMAT.md).
    Keys: pid, attributes, name (<=35 bytes), affinity, entry, guid, parent_pid,
    stop_code, stop_code_id, stop_attr, path, exidx_start, exidx_end, extab_start,
    extab_end."""
    g = p.get
    pb = g("path", "")
    pb = (pb.encode("utf-8") if isinstance(pb, str) else bytes(pb)) + b"\0"
    body = struct.pack("<II", g("pid", 0), g("attributes", 1)) + _fixed_str(g("name", ""), 36, 35)
    body += struct.pack("<4I", g("affinity", 0), g("entry", 0), g("guid", 0), g("parent_pid", 0))
    body += struct.pack("<5I", STOP_REASON_SIZE, g("stop_code", 0), g("stop_code_id", 0), 0,
                        g("stop_attr", 0))
    body += struct.pack("<I", len(pb)) + _pad4(pb)
    body += struct.pack("<4I", g("exidx_start", 0), g("exidx_end", 0),
                        g("extab_start", 0), g("extab_end", 0))
    return struct.pack("<I", 4 + len(body)) + body


def process_info_res(b0, group, code, seq_bytes, processes):
    """GET_PROCESS_INFO_RES (0x20/0x01), request 00 20 00 00. Validator FUN_1400d0a20."""
    return dbgp_header(b0, group, code, seq_bytes) + struct.pack("<I", len(processes)) + \
        b"".join(process_entry(p) for p in processes)


def attach_process_res(b0, group, code, seq_bytes=None, result=0):
    """ATTACH_PROCESS_RES (0x20/0x11) for request 00 20 10 00 | pid | flags.
    Validator FUN_1400cfe50 needs 0 body bytes: the 12-byte header IS the reply.
    No pid echo. result 0 or 0x20052 = success (FUN_1400f9090)."""
    return dbgp_header(b0, group, code, seq_bytes, result)


def detach_process_res(b0, group, code, seq_bytes=None, result=0):
    """DETACH_PROCESS_RES (0x20/0x13) for request 00 20 12 00 | pid | resume_flag.
    Validator FUN_1400d01c0: header only, result must be 0 for success."""
    return dbgp_header(b0, group, code, seq_bytes, result)


def suspend_process_res(b0, group, code, seq_bytes, process, threads, failed_thread_ids=()):
    """SUSPEND_PROCESS_RES (0x20/0x21) for request 00 20 20 00 | pid (= IProcess.Suspend,
    which returns an IStopNotification + FailedThreads). Validator FUN_1400d21f0,
    consumer FUN_140140270:
      +0x0c u32 thread_count  +0x10 u32 n_failed  +0x14 ProcessInfo entry (its ProcessID
      is the pid check) + thread_count basic ThreadInfo entries + n_failed u32 ids.
    The validator requires >= 0x60 bytes from +0x0c."""
    fl = list(failed_thread_ids)
    return dbgp_header(b0, group, code, seq_bytes) + struct.pack("<II", len(threads), len(fl)) + \
        process_entry(process) + b"".join(thread_entry(t) for t in threads) + \
        b"".join(struct.pack("<I", x) for x in fl)


def resume_process_res(b0, group, code, seq_bytes, pid, thread_ids=()):
    """RESUME_PROCESS_RES (0x20/0x23) for request 00 20 22 00 | pid | u32 n | n*u32 tids
    (IProcess.Resume(pThreadIds) returns a u32 array). Validator FUN_1400d1e10:
    +0x0c pid (checked), +0x10 n, +0x14 n*u32 (returned to the caller as-is)."""
    ids = list(thread_ids)
    return dbgp_header(b0, group, code, seq_bytes) + struct.pack("<II", pid, len(ids)) + \
        b"".join(struct.pack("<I", x) for x in ids)


def app_suspend_res(b0, group, code, seq_bytes, pid):
    """SUSPEND_APPLICATION_RES (0x20/0x25): +0x0c pid only (FUN_1400cfdf0, checked)."""
    return dbgp_header(b0, group, code, seq_bytes) + struct.pack("<I", pid)


def app_resume_res(b0, group, code, seq_bytes, pid):
    """RESUME_APPLICATION_RES (0x20/0x27): +0x0c pid only (FUN_1400cfd90, checked)."""
    return dbgp_header(b0, group, code, seq_bytes) + struct.pack("<I", pid)


def alloc_page_res(b0, group, code, seq_bytes, pid, address):
    """ALLOC_EXEC_PAGE_RES (0x20/0x31, FUN_1400cfc70) / ALLOC_DATA_PAGE_RES (0x20/0x33,
    FUN_1400cfc10) for request 00 20 30|32 00 | pid | page_size:
    +0x0c pid (checked), +0x10 u32 allocated address (returned to the caller)."""
    return dbgp_header(b0, group, code, seq_bytes) + struct.pack("<II", pid, address)


def memblk_entry(m):
    """One GET_MEMBLK_INFO entry, fixed 0x48 bytes (decoder FUN_1400f64d0, names from
    formatter FUN_1401ef640). Keys: id, name (<=31), type, header_address, block_size,
    attributes, unk_38, allocated_size, low_size, high_size."""
    g = m.get
    rec = struct.pack("<II", 0x48, g("id", 0)) + _fixed_str(g("name", ""), 32, 31)
    rec += struct.pack("<8I", g("type", 0), g("header_address", 0), g("block_size", 0),
                       g("attributes", 0), g("unk_38", 0), g("allocated_size", 0),
                       g("low_size", 0), g("high_size", 0))
    assert len(rec) == 0x48
    return rec


def memblk_info_res(b0, group, code, seq_bytes, pid, blocks):
    """GET_MEMBLK_INFO_RES (0x20/0x41) for request 00 20 40 00 | pid. Validator
    FUN_1400d0f80: +0x0c pid (checked), +0x10 count, count*0x48 bytes, entry[0].size==0x48."""
    return dbgp_header(b0, group, code, seq_bytes) + struct.pack("<II", pid, len(blocks)) + \
        b"".join(memblk_entry(m) for m in blocks)


# ---------------------------------------------------------------- SYSTEM group (0x10)

RDMEM_CHUNK = 0x10000   # FUN_14010b790 splits reads larger than this into 0x10000 chunks


def get_conf_res(b0, group, code, seq_bytes, values=(0, 0, 0, 0, 0, 0)):
    """SYSTEM GET_CONF_RES (0x10/0x01) for request 00 10 00 00. Validator FUN_1400d02a0:
    +0x0c u32 size MUST be 0x1c, then 6 u32 (copied to object +0x38..+0x4c by
    FUN_140109170; field names not recovered)."""
    v = (list(values) + [0] * 6)[:6]
    return dbgp_header(b0, group, code, seq_bytes) + struct.pack("<7I", 0x1c, *v)


def rdmem_res(b0, group, code, seq_bytes, pid, data):
    """SYSTEM RDMEM_RES (0x10/0x11) for request 00 10 10 00 | pid | addr | size.
    Validator FUN_1400d1580: +0x0c pid (checked), +0x10 u32 len, +0x14 data[len].
    Return exactly `size` bytes: for reads > 0x10000 psp2tm copies the requested chunk
    size from the data pointer regardless of len. A 0x10000 chunk makes a 0x10014-byte
    payload, so pass it through fragment() (or send one frame if the link allows it)."""
    data = bytes(data)
    return dbgp_header(b0, group, code, seq_bytes) + struct.pack("<II", pid, len(data)) + _pad4(data)


def wrmem_res(b0, group, code, seq_bytes, pid, length):
    """SYSTEM WRMEM_RES (0x10/0x13) for request 00 10 12 00 | pid | addr | len | data(pad4).
    Validator FUN_1400d2520: +0x0c pid (checked, 0x100010), +0x10 u32 written length,
    which MUST equal the request len (else 0x100017)."""
    return dbgp_header(b0, group, code, seq_bytes) + struct.pack("<II", pid, length)


# ---------------------------------------------------------------- SYSTEM notifications
# Target -> host, unsolicited. Routed by FUN_14012c040 (group 0x10) to FUN_14011b140,
# which switches on code and forwards the event to TMAPI clients (FUN_140068190).
# No psp2tm request handler waits for any of these.

def _notif(code, body, b0=0, key=0):
    return struct.pack("<BBBB", b0, 0x10, code, 0) + b"\0\0\0\0" + struct.pack("<I", key) + body


def stop_notification(process, status, thread_id, threads, timestamp=0):
    """0xc0 STOP_NOTIFICATION (FUN_1400d20f0): +0x08 key 0 (single part), +0x0c
    ProcessInfo entry, u32 Status, u32 ThreadId, u32 thread_count, basic ThreadInfo
    entries, u64 tick timestamp (IStopNotification)."""
    return _notif(0xc0, process_entry(process) +
                  struct.pack("<III", status, thread_id, len(threads)) +
                  b"".join(thread_entry(t) for t in threads) + struct.pack("<Q", timestamp))


def thread_create_notification(pid, tid, timestamp=0):
    """0xc2 (FUN_1400d2340 long form): pid, tid, u64 timestamp."""
    return _notif(0xc2, struct.pack("<IIQ", pid, tid, timestamp))


def thread_exit_notification(pid, tid, exit_code=0, timestamp=0):
    """0xc4 (FUN_1400d2400 long form): pid, tid, exit code, u64 timestamp."""
    return _notif(0xc4, struct.pack("<IIIQ", pid, tid, exit_code, timestamp))


def process_create_notification(parent_pid, pid, timestamp=0):
    """0xc6 (FUN_1400d1030 long form): parent pid, pid, u64 timestamp."""
    return _notif(0xc6, struct.pack("<IIQ", parent_pid, pid, timestamp))


def process_exit_notification(pid, exit_code=0, timestamp=0):
    """0xc8 (FUN_1400d10f0 long form): pid, exit code, u64 timestamp."""
    return _notif(0xc8, struct.pack("<IIQ", pid, exit_code, timestamp))


def process_kill_notification(pid, timestamp=0):
    """0xca (FUN_1400d11b0 long form): pid, u64 timestamp."""
    return _notif(0xca, struct.pack("<IQ", pid, timestamp))


def prx_unload_notification(pid, module_id, timestamp=0):
    """0xce (FUN_1400d14c0 long form): pid, module id, u64 timestamp."""
    return _notif(0xce, struct.pack("<IIQ", pid, module_id, timestamp))


def app_suspended_notification(pid, timestamp=0):
    """0xd0 (FUN_1400cfd30): pid, u64 timestamp."""
    return _notif(0xd0, struct.pack("<IQ", pid, timestamp))


def app_resumed_notification(pid, timestamp=0):
    """0xd1 (FUN_1400cfcd0): pid, u64 timestamp."""
    return _notif(0xd1, struct.pack("<IQ", pid, timestamp))


# ---------------------------------------------------------------- THREAD sync/stack/etc.

# Sync-primitive type tags (the u32 that starts each GET_SYNC_INFO record). The consumer
# FUN_14010fa70 switches on this. Values -> TMAPI ISyncPrimitiveInfo collections:
SYNC_TYPES = {
    0x10: "Semaphore", 0x12: "UltMutex", 0x20: "Event", 0x30: "Mutex",
    0x31: "LightWeightMutex", 0x32: "UltQueueDataResourcePool", 0x40: "VariableLengthPool",
    0x41: "FixedLengthPool", 0x42: "UltWaitingQueueResourcePool", 0x43: "UltQueue",
    0x50: "MessagePipe", 0x51: "Callback", 0x52: "UltRWLock", 0x60: "ThreadEventHandler",
    0x70: "RWLock", 0x81: "ConditionalVariable", 0x90: "LightWeightConditionalVariable",
    0x92: "UltConditionalVariable", 0xa0: "Timer", 0xa1: "UltSemaphore",
    0xa2: "UltConditionalVariable2",
}


def sync_record(type_tag, words):
    """Assemble one GET_SYNC_INFO object record. `words` is the u32 list starting at the
    'reserved' word (record word[2]); word[0]=type and word[1]=byte length are prepended.
    The record consumer (FUN_14010fa70) walks records as `ptr += word[1] + 8` and reads
    fields from word[3] onward, so word[2] is unused padding (pass 0)."""
    body = b"".join(struct.pack("<I", w & 0xFFFFFFFF) for w in words)
    return struct.pack("<II", type_tag, len(body)) + body


def _pidtid(pairs):
    return [v for pid, tid in pairs for v in (pid, tid)]


def sync_semaphore(s):
    """type 0x10, ISemaphore. Keys: id, process_id, name(<=31), attributes, ref_count,
    initial_value, value, max_value, process_threads=[(pid,tid)]."""
    g = s.get
    name = list(struct.unpack("<8I", _fixed_str(g("name", ""), 32, 31)))
    pairs = list(g("process_threads", []))
    words = ([0, g("id", 0), g("process_id", 0)] + name +
             [g("attributes", 0), g("ref_count", 1), g("initial_value", 0), g("value", 0),
              g("max_value", 0), len(pairs)] + _pidtid(pairs))
    return sync_record(0x10, words)


def sync_event(s):
    """type 0x20, IEvent. Keys: id, process_id, name, attributes, ref_count,
    initial_value, value, process_threads."""
    g = s.get
    name = list(struct.unpack("<8I", _fixed_str(g("name", ""), 32, 31)))
    pairs = list(g("process_threads", []))
    words = ([0, g("id", 0), g("process_id", 0)] + name +
             [g("attributes", 0), g("ref_count", 1), g("initial_value", 0), g("value", 0),
              len(pairs)] + _pidtid(pairs))
    return sync_record(0x20, words)


def sync_mutex(s):
    """type 0x30, IMutex. Keys: id, process_id, name, attributes, ref_count,
    initial_value, value, thread_owner_id, process_threads, trailing (extra u32)."""
    g = s.get
    name = list(struct.unpack("<8I", _fixed_str(g("name", ""), 32, 31)))
    pairs = list(g("process_threads", []))
    words = ([0, g("id", 0), g("process_id", 0)] + name +
             [g("attributes", 0), g("ref_count", 1), g("initial_value", 0), g("value", 0),
              g("thread_owner_id", 0), len(pairs)] + _pidtid(pairs) + [g("trailing", 0)])
    return sync_record(0x30, words)


def sync_lwmutex(s):
    """type 0x31, ILightWeightMutex (no ProcessId). Keys: id, name, attributes,
    work_address, initial_value, value, thread_owner_id, threads=[tid,...]."""
    g = s.get
    name = list(struct.unpack("<8I", _fixed_str(g("name", ""), 32, 31)))
    tids = list(g("threads", []))
    words = ([0, g("id", 0)] + name +
             [g("attributes", 0), g("work_address", 0), g("initial_value", 0), g("value", 0),
              g("thread_owner_id", 0), len(tids)] + tids)
    return sync_record(0x31, words)


def sync_info_res(b0, group, code, seq_bytes, pid, objects=()):
    """GET_SYNC_PRIM_INFO_LIST_RES (0x30/0x21) for request 00 30 20 00 | pid | nT | types |
    nID | ids. Validator FUN_1400d0cb0: +0x0c u32 pid (echoed; FUN_1400860e0 checks it,
    else 0x100010), then packed records {u32 type, u32 body_len, body} walked until the
    buffer runs out. An **empty list is just the 12-byte header + pid** (16-byte payload)."""
    objs = b"".join(o if isinstance(o, (bytes, bytearray)) else _build_sync(o) for o in objects)
    return dbgp_header(b0, group, code, seq_bytes) + struct.pack("<I", pid) + objs


_SYNC_BUILDERS = {0x10: sync_semaphore, 0x20: sync_event, 0x30: sync_mutex, 0x31: sync_lwmutex}


def _build_sync(o):
    t = o.get("type", 0x10)
    if t in _SYNC_BUILDERS:
        return _SYNC_BUILDERS[t](o)
    return sync_record(t, [0] + list(o.get("words", [])))   # generic passthrough


def suspend_thread_res(b0, group, code, seq_bytes, pid, tid, status=THREAD_STATUS_DORMANT):
    """SUSPEND_THREAD_RES (0x30/0x11) for request 00 30 10 00 | pid | tid.
    Validator FUN_1400d22e0 (0xc bytes). FUN_140085c40 checks pid (0x100010) and tid
    (0x100011). +0x0c pid, +0x10 tid, +0x14 eThreadStatus (IThread.Suspend result)."""
    return dbgp_header(b0, group, code, seq_bytes) + struct.pack("<III", pid, tid, status)


def resume_thread_res(b0, group, code, seq_bytes, pid, tid):
    """RESUME_THREAD_RES (0x30/0x13) for request 00 30 12 00 | pid | tid.
    Validator FUN_1400d1eb0 (8 bytes). FUN_140085610 checks pid and tid. +0x0c pid, +0x10 tid."""
    return dbgp_header(b0, group, code, seq_bytes) + struct.pack("<II", pid, tid)


def stack_info_res(b0, group, code, seq_bytes, entries=()):
    """GET_STACK_INFO_RES (0x30/0x17) for request 00 30 16 00 | pid. Validator FUN_1400d0c10:
    +0x0c u32 count, +0x10 self-sized entries (each first u32 = size). No pid echo. Empty =
    header + u32 0. Entries pass through as raw bytes (layout not reversed)."""
    objs = b"".join(bytes(e) for e in entries)
    return dbgp_header(b0, group, code, seq_bytes) + struct.pack("<I", len(entries)) + objs


def app_object_info_res(b0, group, code, seq_bytes, entries=()):
    """GET_APP_OBJECT_INFO_RES (0x30/0x31) for request 00 30 30 00 | pid. Validator
    FUN_1400d0220: +0x0c u32 count, +0x10 u32 (reserved), +0x14 self-sized entries. No pid
    echo. Empty = header + u32 0 + u32 0."""
    objs = b"".join(bytes(e) for e in entries)
    return dbgp_header(b0, group, code, seq_bytes) + struct.pack("<II", len(entries), 0) + objs


def fiber_stack_info_res(b0, group, code, seq_bytes, entries=()):
    """GET_FIBER_STACK_INFO_RES (0x30/0x33) for request 00 30 32 00 | pid. Validator
    FUN_1400d0310: +0x0c u32 count, +0x10 self-sized entries. No pid echo. Empty = header + u32 0."""
    objs = b"".join(bytes(e) for e in entries)
    return dbgp_header(b0, group, code, seq_bytes) + struct.pack("<I", len(entries)) + objs


# ---------------------------------------------------------------- dispatcher

def build_reply(pay, modules_by_pid=None, threads_by_pid=None, libs_by_pid=None,
                meta_by_module=None, thread_ex=True, processes=None, memblks_by_pid=None,
                read_mem=None, write_mem=None, alloc_page=None, conf=None,
                sync_objects_by_pid=None):
    """Given a DBGP request payload for MODULE/THREAD/PROCESS/SYSTEM, return the response
    payload (or None if not handled). Unknown pids answer with an empty list.
      processes : list of process dicts (process_entry keys) for GET_PROCESS_INFO/SUSPEND
      read_mem  : callable(pid, addr, size) -> bytes   (default: zero-filled)
      write_mem : callable(pid, addr, data) -> None
      alloc_page: callable(pid, size, executable) -> address (default: not handled)
      conf      : 6 u32 for SYSTEM GET_CONF (default: not handled)"""
    if len(pay) < 4:
        return None
    b0, group, code = pay[0], pay[1], pay[2]
    arg = struct.unpack_from("<I", pay, 4)[0] if len(pay) >= 8 else 0
    arg2 = struct.unpack_from("<I", pay, 8)[0] if len(pay) >= 12 else 0
    mods = (modules_by_pid or {})
    thr = (threads_by_pid or {})
    procs = processes or []
    if group == 0x20:
        if code == 0x00:        # left to the caller unless a process list is supplied
            return process_info_res(b0, group, code, None, procs) if processes is not None else None
        if code == 0x10:
            return attach_process_res(b0, group, code)
        if code == 0x12:
            return detach_process_res(b0, group, code)
        if code == 0x20:
            p = next((x for x in procs if x.get("pid") == arg), dict(pid=arg))
            return suspend_process_res(b0, group, code, None, p, thr.get(arg, []))
        if code == 0x22:
            return resume_process_res(b0, group, code, None, arg, [])
        if code == 0x24:
            return app_suspend_res(b0, group, code, None, arg)
        if code == 0x26:
            return app_resume_res(b0, group, code, None, arg)
        if code in (0x30, 0x32) and alloc_page is not None:
            return alloc_page_res(b0, group, code, None, arg, alloc_page(arg, arg2, code == 0x30))
        if code == 0x40:
            return memblk_info_res(b0, group, code, None, arg, (memblks_by_pid or {}).get(arg, []))
        return None
    if group == 0x10:
        if code == 0x00 and conf is not None:
            return get_conf_res(b0, group, code, None, conf)
        if code == 0x10 and len(pay) >= 16:
            size = struct.unpack_from("<I", pay, 12)[0]
            data = read_mem(arg, arg2, size) if read_mem else bytes(size)
            return rdmem_res(b0, group, code, None, arg, data)
        if code == 0x12 and len(pay) >= 16:
            n = struct.unpack_from("<I", pay, 12)[0]
            if write_mem:
                write_mem(arg, arg2, pay[16:16 + n])
            return wrmem_res(b0, group, code, None, arg, n)
        return None
    if group == 0x40 and code == 0x00:
        return module_list_res(b0, group, code, None, mods.get(arg, []), arg)
    if group == 0x40 and code == 0x10:
        return lib_info_res(b0, group, code, None, (libs_by_pid or {}).get(arg, []), arg)
    if group == 0x40 and code == 0x02 and len(pay) >= 12:
        modid = struct.unpack_from("<I", pay, 8)[0]
        return meta_data_res(b0, group, code, None, arg, modid,
                             (meta_by_module or {}).get(modid, b""))
    if group == 0x30 and code == 0x02:
        if not thread_ex:
            return error_res(b0, group, code, None, DBGP_RESULT_UNSUPPORTED)
        return thread_info_ex_res(b0, group, code, None, thr.get(arg, []), arg)
    if group == 0x30 and code == 0x00:
        return thread_info_res(b0, group, code, None, thr.get(arg, []), arg)
    if group == 0x30 and code == 0x14:
        return thread_names_res(b0, group, code, None, thr.get(arg, []))
    if group == 0x30 and code == 0x20:                    # GET_SYNC_INFO (pid | nT | ... | nID | ...)
        return sync_info_res(b0, group, code, None, arg, (sync_objects_by_pid or {}).get(arg, []))
    if group == 0x30 and code == 0x10 and len(pay) >= 12:  # SUSPEND_THREAD (pid | tid)
        return suspend_thread_res(b0, group, code, None, arg, arg2)
    if group == 0x30 and code == 0x12 and len(pay) >= 12:  # RESUME_THREAD (pid | tid)
        return resume_thread_res(b0, group, code, None, arg, arg2)
    if group == 0x30 and code == 0x16:                    # GET_STACK_INFO
        return stack_info_res(b0, group, code, None, [])
    if group == 0x30 and code == 0x30:                    # GET_APP_OBJECT_INFO
        return app_object_info_res(b0, group, code, None, [])
    if group == 0x30 and code == 0x32:                    # GET_FIBER_STACK_INFO
        return fiber_stack_info_res(b0, group, code, None, [])
    return None


# ---------------------------------------------------------------- self-test
# Python mirrors of the psp2tm validators/decoders, used only to check the builders.

def _u32(b, o):
    return struct.unpack_from("<I", b, o)[0]


def _walk(buf, off, count):                      # FUN_1400cdeb0
    for _ in range(count):
        n = _u32(buf, off)
        if off + n > len(buf):
            return False
        off += n
    return True


def _cstr(b, o, limit=None):                     # FUN_1401af520 (len=-1) / FUN_140143460
    raw = b[o:o + limit] if limit else b[o:]
    return raw.split(b"\0", 1)[0].decode("utf-8")


def _check_hdr(p, group, code):
    assert p[1] == group and p[2] == code, "group/code"
    assert struct.unpack_from("<H", p, 4)[0] == 0, "first frame seq must be 0"
    assert _u32(p, 8) == 0, "result"


def _decode_mod_info(p, pid):                    # FUN_1400d06f0 + FUN_1400e3740 + FUN_1400f6570
    _check_hdr(p, 0x40, 0x01)
    assert len(p) >= 0x14 and _u32(p, 0x0c) == pid
    cnt = _u32(p, 0x10)
    assert _walk(p, 0x14, cnt) and (cnt == 0 or _u32(p, 0x14) > 0x4f)
    out, e = [], 0x14
    for _ in range(cnt):
        size, n = _u32(p, e), _u32(p, e + 0x4c)
        m = dict(id=_u32(p, e + 4), sdk_version=_u32(p, e + 8),
                 module_version=struct.unpack_from("<H", p, e + 0xc)[0], type=p[e + 0x10],
                 flags=struct.unpack_from("<H", p, e + 0x12)[0], start_entry=_u32(p, e + 0x14),
                 ref_count=_u32(p, e + 0x18), stop_entry=_u32(p, e + 0x1c),
                 exit_entry=_u32(p, e + 0x20), name=_cstr(p, e + 0x24, 0x1a),
                 status=_u32(p, e + 0x44), guid=_u32(p, e + 0x48),
                 segments=[dict(attr=_u32(p, e + 0x54 + i * 0x14), base=_u32(p, e + 0x58 + i * 0x14),
                                size=_u32(p, e + 0x5c + i * 0x14), align=_u32(p, e + 0x60 + i * 0x14))
                           for i in range(n)])
        t = (n + 4) * 0x14
        if t < size:
            m.update(exidx_start=_u32(p, e + t), exidx_end=_u32(p, e + t + 4),
                     extab_start=_u32(p, e + t + 8), extab_end=_u32(p, e + t + 12))
        out.append(m)
        e += size
    return out


def _decode_threads(p, pid, code):               # FUN_1400d0e40/0da0 + FUN_1400f7020/6e90
    _check_hdr(p, 0x30, code)
    assert _u32(p, 0x0c) == pid
    cnt = _u32(p, 0x10)
    assert _walk(p, 0x14, cnt)
    out, e = [], 0x14
    for _ in range(cnt):
        size = _u32(p, e)
        t = dict(id=_u32(p, e + 4), name=_cstr(p, e + 8), status=_u32(p, e + 0x30),
                 clock_run=struct.unpack_from("<Q", p, e + 0x68)[0],
                 stop_code=_u32(p, e + 0x74), exit_status=_u32(p, e + 0x84), pc=_u32(p, e + 0x9c),
                 wait_detail=struct.unpack_from("<Q", p, e + 0xa4)[0])
        if code == 0x03:
            n = 0x24 if size > 0xcf else 0x20
            t["wait_details"] = list(struct.unpack_from("<%dI" % (n // 4), p, e + 0xac))
        out.append(t)
        e += size
    return out


def _hexdump(b):
    return "\n".join("%04x  %s" % (i, " ".join("%02x" % x for x in b[i:i + 16]))
                     for i in range(0, len(b), 16))


if __name__ == "__main__":
    PID = 0x40010045
    mods = [dict(id=0x40010047, guid=0x12345678, sdk_version=0x03650011, module_version=0x0101,
                 type=MODULE_TYPE_PRX, flags=0, start_entry=0x81000101, name="PCSE00000",
                 status=MODULE_STATUS_LIVE,
                 segments=[dict(attr=5, base=0x81000000, size=0x20000, align=0x10),
                           dict(attr=6, base=0x81100000, size=0x4000, align=0x10)])]
    thr = [dict(id=0x40010049, name="PCSE00000", status=THREAD_STATUS_RUNNING, entry=0x81000101,
                stack_top=0x81200000, stack_size=0x100000, pc=0x81000200, clock_run=123456)]

    p = build_reply(bytes.fromhex("00400000") + struct.pack("<I", PID), {PID: mods})
    d = _decode_mod_info(p, PID)
    assert d[0]["name"] == "PCSE00000" and len(d[0]["segments"]) == 2 and d[0]["guid"] == 0x12345678
    assert d[0]["segments"][1]["base"] == 0x81100000 and "exidx_start" in d[0]
    print("GET_MOD_INFO_RES (%d bytes):\n%s\n" % (len(p), _hexdump(p)))

    p = build_reply(bytes.fromhex("00300200") + struct.pack("<I", PID), threads_by_pid={PID: thr})
    d = _decode_threads(p, PID, 0x03)
    assert d[0]["name"] == "PCSE00000" and d[0]["pc"] == 0x81000200 and len(d[0]["wait_details"]) == 9
    print("GET_THREAD_INFO_EX_RES (%d bytes):\n%s\n" % (len(p), _hexdump(p)))

    p = build_reply(bytes.fromhex("00300000") + struct.pack("<I", PID), threads_by_pid={PID: thr})
    d = _decode_threads(p, PID, 0x01)
    assert d[0]["id"] == 0x40010049 and d[0]["clock_run"] == 123456
    print("GET_THREAD_INFO_RES (%d bytes):\n%s\n" % (len(p), _hexdump(p)))

    p = build_reply(bytes.fromhex("00300200") + struct.pack("<I", PID), thread_ex=False)
    assert _u32(p, 8) == DBGP_RESULT_UNSUPPORTED and len(p) == 12

    big = module_list_res(0, 0x40, 0, None, mods * 400, PID)
    parts = fragment(big, 0x1000)
    joined = parts[0] + b"".join(x[12:] for x in parts[1:])
    assert joined[:6] == big[:6] and joined[7:] == big[7:] and len(parts) > 1
    assert all(struct.unpack_from("<H", x, 4)[0] == i for i, x in enumerate(parts))
    assert all(x[6] & 1 for x in parts[:-1]) and not parts[-1][6] & 1
    _decode_mod_info(joined, PID)
    print("self-test OK (%d modules fragmented into %d frames)" % (400, len(parts)))

    # ---- PROCESS / SYSTEM
    proc = dict(pid=PID, attributes=PROC_ATTR_DEBUGGABLE | PROC_ATTR_ATTACHED | 1, name="PCSE00000",
                path="ux0:app/PCSE00000/eboot.bin")
    req = bytes.fromhex("00201000") + struct.pack("<II", PID, 0)          # Razor's ATTACH
    p = build_reply(req)
    _check_hdr(p, 0x20, 0x11)
    assert len(p) == 12                                                    # FUN_1400cfe50: 0 body bytes
    print("ATTACH_PROCESS_RES: %s" % p.hex(" "))

    p = build_reply(bytes.fromhex("00201200") + struct.pack("<II", PID, 1))
    _check_hdr(p, 0x20, 0x13)                                              # FUN_1400d01c0
    assert len(p) == 12

    p = build_reply(bytes.fromhex("00202000") + struct.pack("<I", PID), threads_by_pid={PID: thr},
                    processes=[proc])
    _check_hdr(p, 0x20, 0x21)                                              # FUN_1400d21f0
    assert len(p) >= 0x0c + 0x60
    tcount, nfail, psize = _u32(p, 0x0c), _u32(p, 0x10), _u32(p, 0x14)
    assert _u32(p, 0x18) == PID                                            # FUN_140085b60 pid check
    assert psize > 0x57 and _u32(p, 0x14 + 0x40) == 0x14                   # proc entry sanity
    tstart = 0x14 + psize
    assert _walk(p, tstart, tcount)
    off = tstart
    for _ in range(tcount):
        off += _u32(p, off)
    assert off + 4 * nfail <= len(p)
    assert _cstr(p, 0x14 + 0x0c) == "PCSE00000" and _cstr(p, 0x14 + 0x58) == proc["path"]

    p = build_reply(bytes.fromhex("00202200") + struct.pack("<III", PID, 1, 0x40010049))
    _check_hdr(p, 0x20, 0x23)
    assert _u32(p, 0x0c) == PID and len(p) >= 0x14 + 4 * _u32(p, 0x10)    # FUN_1400d1e10

    p = build_reply(bytes.fromhex("00204000") + struct.pack("<I", PID),
                    memblks_by_pid={PID: [dict(id=1, name="blk", block_size=0x1000)]})
    _check_hdr(p, 0x20, 0x41)                                              # FUN_1400d0f80
    assert _u32(p, 0x0c) == PID and len(p) >= 0x14 + 0x48 * _u32(p, 0x10) and _u32(p, 0x14) == 0x48

    mem = {0x81000000: b"LIBPERF!" * 0x3000}
    rd = lambda pid, a, n: (mem[0x81000000] + bytes(n))[a - 0x81000000:a - 0x81000000 + n]
    for size in (0x20, 0x10000):
        p = build_reply(bytes.fromhex("00101000") + struct.pack("<III", PID, 0x81000000, size),
                        read_mem=rd)
        _check_hdr(p, 0x10, 0x11)                                          # FUN_1400d1580
        assert _u32(p, 0x0c) == PID and _u32(p, 0x10) == size and len(p) >= 0x14 + size
        assert p[0x14:0x1c] == b"LIBPERF!"
        parts = fragment(p)
        joined = parts[0] + b"".join(x[12:] for x in parts[1:])
        assert joined[7:] == p[7:] and all(len(x) + 16 <= 0x10000 for x in parts)
    print("RDMEM_RES 0x10000 -> %d frame(s)" % len(parts))

    wrote = []
    p = build_reply(bytes.fromhex("00101200") + struct.pack("<III", PID, 0x81001000, 4) + b"\1\0\0\0",
                    write_mem=lambda pid, a, d: wrote.append((pid, a, d)))
    _check_hdr(p, 0x10, 0x13)                                              # FUN_1400d2520
    assert _u32(p, 0x0c) == PID and _u32(p, 0x10) == 4 and wrote == [(PID, 0x81001000, b"\1\0\0\0")]

    # ---- THREAD GET_SYNC_INFO (the blocker): empty and populated
    def _decode_sync(p, pid):                                            # FUN_1400d0cb0 + FUN_14010fa70
        _check_hdr(p, 0x30, 0x21)
        assert _u32(p, 0x0c) == pid, "sync pid echo"
        objs, off = [], 0x10
        while off + 8 <= len(p):
            t, blen = _u32(p, off), _u32(p, off + 4)
            assert off + blen <= len(p), "sync record body in bounds"
            objs.append((t, off))
            off += blen + 8
        return objs

    req = bytes.fromhex("00302000") + struct.pack("<III", 0x40010003, 0, 0)   # Razor's request
    p = build_reply(req)
    assert _decode_sync(p, 0x40010003) == [] and len(p) == 16                 # empty list
    print("GET_SYNC_INFO (empty): %s" % p.hex(" "))

    syncs = [dict(type=0x10, id=0x40010101, process_id=0x40010003, name="mySema",
                  initial_value=1, value=1, max_value=4, process_threads=[(0x40010003, 0x40010049)]),
             dict(type=0x30, id=0x40010102, process_id=0x40010003, name="myMutex",
                  thread_owner_id=0x40010049, process_threads=[]),
             dict(type=0x31, id=0x40010103, name="lwMutex", threads=[0x40010049])]
    p = build_reply(bytes.fromhex("00302000") + struct.pack("<III", 0x40010003, 0, 0),
                    sync_objects_by_pid={0x40010003: syncs})
    got = _decode_sync(p, 0x40010003)
    assert [t for t, _ in got] == [0x10, 0x30, 0x31]
    t, off = got[0]
    assert _cstr(p, off + 8 + 0x0c) == "mySema" and _u32(p, off + 8 + 0x08) == 0x40010003
    print("GET_SYNC_INFO (%d objects, %d bytes) OK" % (len(got), len(p)))

    for hexreq, rescode in [("00301000", 0x11), ("00301200", 0x13), ("00301600", 0x17),
                            ("00303000", 0x31), ("00303200", 0x33)]:
        p = build_reply(bytes.fromhex(hexreq) + struct.pack("<II", 0x40010003, 0x40010049))
        assert p[1] == 0x30 and p[2] == rescode and _u32(p, 8) == 0
    print("SUSPEND/RESUME_THREAD, STACK/APP_OBJECT/FIBER_STACK info OK")

    n = stop_notification(proc, 0, 0x40010049, thr, 42)                  # FUN_1400d20f0
    assert n[1] == 0x10 and n[2] == 0xc0 and len(n) >= 0x0c + 0x58
    ps = _u32(n, 0x0c)
    tc = _u32(n, 0x0c + ps + 8)
    assert _walk(n, 0x18 + ps, tc)
    off = 0x18 + ps
    for _ in range(tc):
        off += _u32(n, off)
    assert struct.unpack_from("<Q", n, off)[0] == 42
    print("PROCESS/SYSTEM self-test OK")
