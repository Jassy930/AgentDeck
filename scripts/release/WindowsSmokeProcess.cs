using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Runtime.ExceptionServices;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace AgentDeck {
    // Assign while suspended: no child can escape before the kill-on-close job owns the process.
    public static class ReleaseSmokeProcess {
        [StructLayout(LayoutKind.Sequential)] struct SecurityAttributes {
            public int Length; public IntPtr Descriptor; public int Inherit;
        }
        [StructLayout(LayoutKind.Sequential)] struct StartupInfo {
            public int Size; public IntPtr Reserved, Desktop, Title;
            public int X, Y, XSize, YSize, XCount, YCount, Fill, Flags;
            public short ShowWindow, ReservedSize; public IntPtr ReservedBytes, Input, Output, Error;
        }
        [StructLayout(LayoutKind.Sequential)] struct ProcessInfo {
            public IntPtr Process, Thread; public int ProcessId, ThreadId;
        }
        [StructLayout(LayoutKind.Sequential)] struct BasicLimits {
            public long ProcessTime, JobTime; public uint Flags;
            public UIntPtr MinimumWorkingSet, MaximumWorkingSet;
            public uint ActiveProcessLimit; public UIntPtr Affinity;
            public uint PriorityClass, SchedulingClass;
        }
        [StructLayout(LayoutKind.Sequential)] struct IoCounters {
            public ulong ReadOperations, WriteOperations, OtherOperations, ReadBytes, WriteBytes, OtherBytes;
        }
        [StructLayout(LayoutKind.Sequential)] struct ExtendedLimits {
            public BasicLimits Basic; public IoCounters Io;
            public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
        }
        [StructLayout(LayoutKind.Sequential)] struct BasicAccounting {
            public long TotalUserTime, TotalKernelTime, PeriodUserTime, PeriodKernelTime;
            public uint PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses;
        }
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateJobObject(IntPtr attributes, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool SetInformationJobObject(IntPtr job, int type, ref ExtendedLimits limits, uint length);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool QueryInformationJobObject(IntPtr job, int type, out BasicAccounting accounting,
            uint length, IntPtr returnedLength);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern IntPtr CreateFile(string name, uint access, uint sharing, ref SecurityAttributes security,
            uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool CreateProcess(string application, StringBuilder command, IntPtr processSecurity,
            IntPtr threadSecurity, bool inheritHandles, uint flags, IntPtr environment, string directory,
            ref StartupInfo startup, out ProcessInfo process);
        [DllImport("kernel32.dll", SetLastError = true)] static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr process, uint code);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateJobObject(IntPtr job, uint code);
        [DllImport("kernel32.dll", SetLastError = true)] static extern bool CloseHandle(IntPtr handle);

        static void Check(bool success, string action) {
            if (!success) throw new Win32Exception(Marshal.GetLastWin32Error(), action);
        }
        static void RecordFailure(List<Exception> errors, Action action) {
            try { action(); } catch (Exception error) { errors.Add(error); }
        }
        static void WaitForEmptyJob(IntPtr job) {
            var timer = Stopwatch.StartNew();
            while (true) {
                BasicAccounting accounting;
                Check(QueryInformationJobObject(job, 1, out accounting,
                    (uint)Marshal.SizeOf<BasicAccounting>(), IntPtr.Zero), "QueryInformationJobObject");
                if (accounting.ActiveProcesses == 0) return;
                if (timer.ElapsedMilliseconds >= 5000)
                    throw new TimeoutException("Release smoke cleanup: job still contains " + accounting.ActiveProcesses + " processes");
                Thread.Sleep(25);
            }
        }
        static string Quote(string value) {
            var result = new StringBuilder("\"");
            int slashes = 0;
            foreach (char c in value) {
                if (c == '\\') { slashes++; continue; }
                result.Append('\\', c == '"' ? slashes * 2 + 1 : slashes);
                result.Append(c); slashes = 0;
            }
            return result.Append('\\', slashes * 2).Append('"').ToString();
        }
        public static int Run(string executable, string[] arguments, string directory,
            Dictionary<string,string> environment, string output, int timeoutMilliseconds) {
            if (timeoutMilliseconds < 1) throw new ArgumentOutOfRangeException("timeoutMilliseconds");
            IntPtr job = IntPtr.Zero, log = IntPtr.Zero, input = IntPtr.Zero, block = IntPtr.Zero;
            var process = new ProcessInfo();
            var errors = new List<Exception>();
            int result = 0;
            try {
                job = CreateJobObject(IntPtr.Zero, null);
                Check(job != IntPtr.Zero, "CreateJobObject");
                var limits = new ExtendedLimits(); limits.Basic.Flags = 0x2000; // KILL_ON_JOB_CLOSE
                Check(SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf(limits)), "SetInformationJobObject");
                var security = new SecurityAttributes { Length = Marshal.SizeOf<SecurityAttributes>(), Inherit = 1 };
                log = CreateFile(output, 0x40000000, 3, ref security, 2, 0x80, IntPtr.Zero);
                Check(log != new IntPtr(-1), "Create output log");
                input = CreateFile("NUL", 0x80000000, 3, ref security, 3, 0x80, IntPtr.Zero);
                Check(input != new IntPtr(-1), "Open NUL input");
                var startup = new StartupInfo { Size = Marshal.SizeOf<StartupInfo>(), Flags = 0x100,
                    Input = input, Output = log, Error = log };
                string environmentText = string.Join("\0", environment.OrderBy(e => e.Key, StringComparer.OrdinalIgnoreCase)
                    .Select(e => e.Key + "=" + e.Value)) + "\0\0";
                block = Marshal.StringToHGlobalUni(environmentText);
                var command = new StringBuilder(string.Join(" ", new[] { executable }.Concat(arguments).Select(Quote)));
                Check(CreateProcess(executable, command, IntPtr.Zero, IntPtr.Zero, true, 0x08000404, block,
                    directory, ref startup, out process), "CreateProcess"); // suspended + Unicode env + no console
                Check(AssignProcessToJobObject(job, process.Process), "AssignProcessToJobObject");
                Check(ResumeThread(process.Thread) != 0xffffffff, "ResumeThread");
                uint wait = WaitForSingleObject(process.Process, (uint)timeoutMilliseconds);
                if (wait == 258) throw new TimeoutException("Release smoke process timed out: " + executable);
                Check(wait == 0, "WaitForSingleObject");
                uint exitCode; Check(GetExitCodeProcess(process.Process, out exitCode), "GetExitCodeProcess");
                result = unchecked((int)exitCode);
            } catch (Exception error) {
                errors.Add(error);
            } finally {
                // Root exit does not imply descendant exit; confirm the job is empty before releasing logs.
                if (job != IntPtr.Zero) {
                    RecordFailure(errors, () => Check(TerminateJobObject(job, 124), "TerminateJobObject"));
                    RecordFailure(errors, () => WaitForEmptyJob(job));
                }
                if (process.Process != IntPtr.Zero) {
                    RecordFailure(errors, () => {
                        // Assignment can fail while the new process is still suspended outside the job.
                        uint state = WaitForSingleObject(process.Process, 0);
                        if (state == 258) Check(TerminateProcess(process.Process, 124), "TerminateProcess");
                        else Check(state == 0, "Check root process exit");
                        if (WaitForSingleObject(process.Process, 5000) != 0)
                            throw new TimeoutException("Release smoke cleanup: root process did not exit");
                    });
                }
                foreach (IntPtr handle in new[] { job, process.Process, process.Thread, log, input }) {
                    if (handle != IntPtr.Zero && handle != new IntPtr(-1))
                        RecordFailure(errors, () => Check(CloseHandle(handle), "CloseHandle"));
                }
                if (block != IntPtr.Zero) Marshal.FreeHGlobal(block);
            }
            if (errors.Count > 0 && result != 0)
                errors.Insert(0, new Exception("Release smoke process exited " + result));
            if (errors.Count == 1) ExceptionDispatchInfo.Capture(errors[0]).Throw();
            if (errors.Count > 1) throw new AggregateException("Release smoke execution or cleanup failed", errors);
            return result;
        }
    }
}
