namespace WRMS.Agent.Services;

using System.Diagnostics;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;

/// <summary>
/// Launches and monitors the lightweight '--session-tracker' helper inside the active logged-in desktop session
/// when WRMS.Agent runs as a Session-0 Windows Service (LocalSystem).
/// </summary>
public sealed class UserSessionLauncher : IDisposable
{
    private readonly ILogger<UserSessionLauncher> _logger;
    private int? _trackedHelperPid;
    private uint _trackedSessionId;

    public UserSessionLauncher(ILogger<UserSessionLauncher> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public void EnsureSessionTrackerRunning()
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        // If running directly in an interactive user console/session, Worker handles tracking directly
        if (Environment.UserInteractive)
        {
            return;
        }

        uint activeSessionId = WTSGetActiveConsoleSessionId();
        if (activeSessionId == 0xFFFFFFFF || activeSessionId == 0)
        {
            return;
        }

        // Check if our spawned helper process is still alive in the active console session
        if (_trackedHelperPid.HasValue && _trackedSessionId == activeSessionId)
        {
            try
            {
                using var existing = Process.GetProcessById(_trackedHelperPid.Value);
                if (!existing.HasExited && existing.SessionId == (int)activeSessionId)
                {
                    return;
                }
            }
            catch
            {
                _trackedHelperPid = null;
            }
        }

        // Also check if another --session-tracker instance of WRMS.Agent is already running in this session
        if (IsAnotherHelperRunningInSession((int)activeSessionId))
        {
            return;
        }

        try
        {
            var exePath = Environment.ProcessPath;
            if (string.IsNullOrWhiteSpace(exePath) || !File.Exists(exePath))
            {
                exePath = Path.Combine(AppContext.BaseDirectory, "WRMS.Agent.exe");
            }
            if (!File.Exists(exePath))
            {
                return;
            }

            if (LaunchInUserSession(activeSessionId, exePath, $"--session-tracker --parent-pid {Environment.ProcessId}", out int childPid))
            {
                _trackedHelperPid = childPid;
                _trackedSessionId = activeSessionId;
                _logger.LogInformation("Launched user-session activity tracker (PID {Pid}) in desktop session {SessionId}.",
                    childPid, activeSessionId);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not start user-session tracker helper in session {SessionId}.", activeSessionId);
        }
    }

    public void StopSessionTracker()
    {
        if (_trackedHelperPid.HasValue)
        {
            try
            {
                using var proc = Process.GetProcessById(_trackedHelperPid.Value);
                if (!proc.HasExited)
                {
                    proc.Kill(entireProcessTree: true);
                }
            }
            catch { }
            finally
            {
                _trackedHelperPid = null;
            }
        }
    }

    public void Dispose()
    {
        StopSessionTracker();
    }

    private bool IsAnotherHelperRunningInSession(int sessionId)
    {
        try
        {
            int selfPid = Environment.ProcessId;
            foreach (var p in Process.GetProcessesByName("WRMS.Agent"))
            {
                try
                {
                    if (p.Id != selfPid && p.SessionId == sessionId && !p.HasExited)
                    {
                        _trackedHelperPid = p.Id;
                        _trackedSessionId = (uint)sessionId;
                        return true;
                    }
                }
                catch { }
                finally
                {
                    p.Dispose();
                }
            }
        }
        catch { }
        return false;
    }

    private static bool LaunchInUserSession(uint sessionId, string exePath, string arguments, out int processId)
    {
        processId = 0;
        IntPtr userToken = IntPtr.Zero;
        IntPtr dupToken = IntPtr.Zero;
        IntPtr envBlock = IntPtr.Zero;

        try
        {
            if (!WTSQueryUserToken(sessionId, out userToken) || userToken == IntPtr.Zero)
            {
                return false;
            }

            var sa = new SECURITY_ATTRIBUTES { nLength = Marshal.SizeOf<SECURITY_ATTRIBUTES>() };
            if (!DuplicateTokenEx(
                userToken,
                MAXIMUM_ALLOWED,
                ref sa,
                SECURITY_IMPERSONATION_LEVEL.SecurityIdentification,
                TOKEN_TYPE.TokenPrimary,
                out dupToken))
            {
                return false;
            }

            CreateEnvironmentBlock(out envBlock, dupToken, false);

            var si = new STARTUPINFO
            {
                cb = Marshal.SizeOf<STARTUPINFO>(),
                lpDesktop = @"winsta0\default"
            };

            string cmdLine = $"\"{exePath}\" {arguments}";
            uint creationFlags = NORMAL_PRIORITY_CLASS | CREATE_NO_WINDOW | (envBlock != IntPtr.Zero ? CREATE_UNICODE_ENVIRONMENT : 0);

            if (!CreateProcessAsUser(
                dupToken,
                exePath,
                cmdLine,
                ref sa,
                ref sa,
                false,
                creationFlags,
                envBlock,
                AppContext.BaseDirectory,
                ref si,
                out var pi))
            {
                return false;
            }

            processId = pi.dwProcessId;
            if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
            if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
            return true;
        }
        finally
        {
            if (envBlock != IntPtr.Zero) DestroyEnvironmentBlock(envBlock);
            if (dupToken != IntPtr.Zero) CloseHandle(dupToken);
            if (userToken != IntPtr.Zero) CloseHandle(userToken);
        }
    }

    private const uint MAXIMUM_ALLOWED = 0x02000000;
    private const uint NORMAL_PRIORITY_CLASS = 0x00000020;
    private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
    private const uint CREATE_NO_WINDOW = 0x08000000;

    private enum SECURITY_IMPERSONATION_LEVEL
    {
        SecurityAnonymous,
        SecurityIdentification,
        SecurityImpersonation,
        SecurityDelegation
    }

    private enum TOKEN_TYPE
    {
        TokenPrimary = 1,
        TokenImpersonation
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public bool bInheritHandle;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct STARTUPINFO
    {
        public int cb;
        public string? lpReserved;
        public string? lpDesktop;
        public string? lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool WTSQueryUserToken(uint sessionId, out IntPtr phToken);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        ref SECURITY_ATTRIBUTES lpTokenAttributes,
        SECURITY_IMPERSONATION_LEVEL impersonationLevel,
        TOKEN_TYPE tokenType,
        out IntPtr phNewToken);

    [DllImport("userenv.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateEnvironmentBlock(out IntPtr lpEnvironment, IntPtr hToken, bool bInherit);

    [DllImport("userenv.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool DestroyEnvironmentBlock(IntPtr lpEnvironment);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateProcessAsUser(
        IntPtr hToken,
        string? lpApplicationName,
        string? lpCommandLine,
        ref SECURITY_ATTRIBUTES lpProcessAttributes,
        ref SECURITY_ATTRIBUTES lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string? lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr hObject);
}
