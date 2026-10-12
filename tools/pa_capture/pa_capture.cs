// pa_capture -- drives a Performance Analysis capture through Target Manager (TMAPI), the way
// Razor does, without Razor's UI. Used to test retail_razorconnect + rrc_pa on the console.
//
//   pa_capture procs
//   pa_capture cpu <seconds> <out.raw> [pid]        ARM (CPU) trace of the debuggable process
//   pa_capture gpu <seconds> <out.pmon> [pid]       GPU trace (CreateGpuTrace), buffer 0
//
// Build: build.cmd (csc from .NET Framework 4, references the SDK's Interop.PSP2TMAPILib.dll).
// Check a CPU trace with: python ..\check_trace_file.py <out.raw>

using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
using PSP2TMAPILib;

static class PaCapture
{
    const uint ATTR_DEBUGGABLE = 0x10000;
    const uint ATTR_ATTACHED = 0x20000;

    static Stopwatch clock = Stopwatch.StartNew();

    static void Log(string fmt, params object[] args)
    {
        Console.WriteLine("[{0,8:F3}] {1}", clock.Elapsed.TotalSeconds, string.Format(fmt, args));
    }

    static T Timed<T>(string what, Func<T> f)
    {
        var t0 = clock.Elapsed.TotalMilliseconds;
        T r = f();
        Log("{0}: {1:F0} ms", what, clock.Elapsed.TotalMilliseconds - t0);
        return r;
    }

    static void Timed(string what, Action f)
    {
        Timed<int>(what, () => { f(); return 0; });
    }

    static uint Debuggable(ITarget tgt, bool print)
    {
        uint pid = 0;
        foreach (IProcessInfo pi in tgt.ProcessInfoSnapshot)
        {
            if (print)
                Console.WriteLine("  0x{0:x8}  attrs 0x{1:x8}{2}{3}  {4}  {5}", pi.Id, pi.Attributes,
                    (pi.Attributes & ATTR_DEBUGGABLE) != 0 ? " debuggable" : "",
                    (pi.Attributes & ATTR_ATTACHED) != 0 ? " attached" : "", pi.Name, pi.Path);
            if ((pi.Attributes & ATTR_DEBUGGABLE) != 0 && pid == 0)
                pid = pi.Id;
        }
        return pid;
    }

    // Receives the target's STOP_NOTIFICATION (the virtual HUD's "trace complete" breakpoint).
    [System.Runtime.InteropServices.ComVisible(true)]
    public class DebugSink : IEventDebug
    {
        public readonly ManualResetEvent Stopped = new ManualResetEvent(false);
        public uint Pid, Tid, Pc, Status;

        public void OnStopNotification(IStopNotification n, ulong tick)
        {
            Status = n.Status;
            Tid = n.ThreadId;
            Pid = n.ProcessInfo.Id;
            foreach (IThreadInfo t in n.Threads)
                if (t.Id == Tid)
                    Pc = t.PC;
            Stopped.Set();
        }
        public void OnProcessCreate(uint a, uint b, uint c, ulong d) { }
        public void OnProcessExit(uint a, uint b, uint c, ulong d) { }
        public void OnProcessKill(uint a, uint b, ulong c) { }
        public void OnPRXModuleLoad(uint a, uint b, uint c, ulong d, IPRXLoadedData e) { }
        public void OnPRXModuleUnload(uint a, uint b, uint c, ulong d) { }
        public void OnThreadCreate(uint a, uint b, ulong c) { }
        public void OnThreadExit(uint a, uint b, uint c, ulong d) { }
        public void OnApplicationSuspended(uint a, ulong b) { }
        public void OnApplicationResumed(uint a, ulong b) { }
    }

    static byte[] Command(uint cmd, string arg)
    {
        var buf = new byte[0x204];
        BitConverter.GetBytes(cmd).CopyTo(buf, 0);
        if (arg != null)
            System.Text.Encoding.ASCII.GetBytes(arg).CopyTo(buf, 4);
        return buf;
    }

    // Razor's GPU Trace against the HUD, step by step (GPU_TRACE_SESSION.md,
    // DBGP_BREAKPOINT_STOP.md): the .pmon lands in <dir>\tmp.pmon.
    static int HudTrace(ITarget tgt, string dir)
    {
        uint pid = Debuggable(tgt, true);
        IProcessInfo pi = null;
        foreach (IProcessInfo p in tgt.ProcessInfoSnapshot)
            if (p.Id == pid)
                pi = p;
        if (pi == null)
        {
            Log("no debuggable process");
            return 1;
        }
        IProcess proc = pi.ProcessInterface;
        IModule hud = null;
        foreach (IModule m in proc.Modules)
            if (m.Name == "SceRazorHud")
                hud = m;
        if (hud == null)
        {
            Log("no SceRazorHud module in 0x{0:x8}", pid);
            return 1;
        }
        uint info = 0;
        foreach (ISegmentInfo s in hud.ModuleSegments)
        {
            if ((s.Attributes & 1) == 0)
                continue;
            byte[] code = (byte[])Timed(string.Format("RDMEM segment 0x{0:x8}+0x{1:x}", s.BaseAddress, s.Size),
                () => proc.GetMemory(s.BaseAddress, s.Size));
            for (int i = 0; i + 12 <= code.Length; i += 4)
                if (BitConverter.ToUInt32(code, i) == 0xBEBABEB0 && BitConverter.ToUInt32(code, i + 4) == 0xBE77BEFE)
                    info = BitConverter.ToUInt32(code, i + 8);
        }
        if (info == 0)
        {
            Log("marker not found");
            return 1;
        }
        byte[] st = (byte[])proc.GetMemory(info, 0x20);
        uint version = BitConverter.ToUInt32(st, 0), size = BitConverter.ToUInt32(st, 4);
        uint bp = BitConverter.ToUInt32(st, 0xc), cmd = BitConverter.ToUInt32(st, 0x10);
        Log("info 0x{0:x8}: version {1} size 0x{2:x} bp 0x{3:x8} cmd 0x{4:x8}", info, version, size, bp, cmd);
        if (version != 1 || size != 0x20 || bp == 0)
            return 1;

        Directory.CreateDirectory(dir);
        string pmon = Path.Combine(dir, "tmp.pmon"), ini = Path.Combine(dir, "tmp_settings.ini");
        File.Delete(pmon);
        Func<string, string> host0 = local => "host0:" + local.Replace('\\', '/');
        File.WriteAllText(ini, "trace=1\r\ntrace_metrics_group=0\r\ntrace_size=low\r\ntrace_rate=medium\r\n" +
            "trace_filename_count_len=0\r\ntrace_filename=" + host0(pmon));

        var sink = new DebugSink();
        tgt.AdviseDebugEvents(sink);
        try
        {
            Timed("WRMEM arm", () => proc.SetMemory(cmd, Command(1, host0(ini))));
            uint opSize, op;
            uint id = Timed("SET_SWBRKPT", () => proc.SetSoftwareBreakpoint(0xFFFFFFFF, bp & ~1u,
                (bp & 1) != 0 ? eSoftwareBreakPtAttr.SWBREAKPT_ATTR_16BIT_MODE : eSoftwareBreakPtAttr.SWBREAKPT_ATTR_32BIT_MODE,
                0, null, out opSize, out op));
            Log("breakpoint id {0}", id);
            Timed("Resume", () => proc.Resume(null));
            bool stopped = Timed("wait for the stop", () => sink.Stopped.WaitOne(TimeSpan.FromSeconds(90)));
            Log("stopped {0}: pid 0x{1:x8} tid 0x{2:x8} pc 0x{3:x8} status 0x{4:x}", stopped, sink.Pid, sink.Tid, sink.Pc, sink.Status);
            Timed("WRMEM stop", () => proc.SetMemory(cmd, Command(2, null)));
            Timed("CLEAR_SWBRKPT", () => proc.ClearSoftwareBreakpoint(id));
            Timed("WRMEM teardown", () => proc.SetMemory(cmd, Command(4, null)));
            if (File.Exists(pmon))
                Log("{0}: {1} bytes", pmon, new FileInfo(pmon).Length);
            else
                Log("{0} was not written", pmon);
            return stopped && File.Exists(pmon) && sink.Pc == (bp & ~1u) ? 0 : 1;
        }
        finally
        {
            tgt.UnadviseDebugEvents(sink);
        }
    }

    [MTAThread]
    static int Main(string[] args)
    {
        if (args.Length < 1)
        {
            Console.Error.WriteLine("usage: pa_capture procs | cpu <seconds> <out.raw> [pid] | gpu <seconds> <out.pmon> [pid]");
            return 2;
        }
        var tm = new PSP2TMAPI();
        tm.CheckCompatibility((uint)eCompatibleVersion.BuildVersion);
        ITarget tgt = tm.Targets.DefaultTarget;
        if (tgt == null)
        {
            Console.Error.WriteLine("no default target");
            return 1;
        }
        tgt.RequestConnection();
        try
        {
            Log("target {0} ({1}), power {2}", tgt.Name, tgt.LastKnownHost, tgt.PowerStatus);
            if (args[0] == "procs")
            {
                Debuggable(tgt, true);
                return 0;
            }
            if (args[0] == "hud")
                return HudTrace(tgt, args.Length > 1 ? args[1] : Path.Combine(Path.GetTempPath(), "rrc_hud_test"));
            bool gpu = args[0] == "gpu";
            if (args.Length < 3 || (!gpu && args[0] != "cpu"))
            {
                Console.Error.WriteLine("bad arguments");
                return 2;
            }
            double seconds = double.Parse(args[1]);
            string outPath = args[2];
            uint pid = args.Length > 3 ? Convert.ToUInt32(args[3], 16) : Debuggable(tgt, true);
            Log("traced pid 0x{0:x8}", pid);

            IPerformanceAnalysis pa = tgt.PAInterface;
            Timed("Open", () => pa.Open());
            try
            {
                uint freq = Timed("TimebaseFrequency", () => pa.TimebaseFrequency);
                uint avail = Timed("TraceBufferAvailableSize", () => pa.TraceBufferAvailableSize);
                Log("timebase {0} MHz, buffer {1} bytes", freq, avail);
                if (avail > 0x4000000) avail = 0x4000000;
                Timed("ConfigNormalTraceBuffer", () => pa.ConfigNormalTraceBuffer(0, 0, avail, 0x1f));
                if (gpu)
                {
                    // Values are placeholders until the plugin's GPU path defines what it uses.
                    Timed("CreateGpuTrace", () => pa.CreateGpuTrace(0, 1000, 1000,
                        new uint[4], new uint[4], new uint[4], new uint[4]));
                }
                else
                {
                    // Razor: trace mode 0, sample mode 6 (PC sampling), sample period 1000.
                    Timed("CreateArmTrace", () => pa.CreateArmTrace(0, 6, 0, 1000, pid));
                }
                Timed("StartCapture", () => pa.StartCapture());
                Thread.Sleep(TimeSpan.FromSeconds(seconds));
                Timed("StopCapture", () => pa.StopCapture());
                uint status = 0, b1 = 0, b2 = 0;
                Timed("GetTraceInfo", () => pa.GetTraceInfo(out status, out b1, out b2));
                Log("trace info: status {0}, buffer1 {1} bytes, buffer2 {2} bytes", status, b1, b2);
                using (var f = File.Create(outPath))
                {
                    uint off = 0;
                    while (off < b1)
                    {
                        uint n = Math.Min(b1 - off, 0x400000u);
                        uint o = off;
                        byte[] chunk = (byte[])Timed(string.Format("FetchTraceData @{0}", off),
                            () => pa.FetchTraceData(0, o, n));
                        if (chunk == null || chunk.Length == 0)
                        {
                            Log("empty chunk at {0}", off);
                            break;
                        }
                        f.Write(chunk, 0, chunk.Length);
                        off += (uint)chunk.Length;
                    }
                    Log("wrote {0} bytes to {1}", off, outPath);
                }
            }
            finally
            {
                Timed("Close", () => pa.Close());
            }
            return 0;
        }
        catch (System.Runtime.InteropServices.COMException e)
        {
            Log("COM error 0x{0:x8}: {1}", e.ErrorCode, e.Message);
            return 1;
        }
        finally
        {
            tgt.ReleaseConnection();
        }
    }
}
