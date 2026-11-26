namespace WRMS.Agent.Services;

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using WRMS.Agent.Models;

/// <summary>
/// Samples the true Windows active foreground application and keyboard/mouse idle state every second
/// inside the logged-in user's desktop session, persisting accurate daily screen-time metrics.
/// </summary>
public sealed class ForegroundUsageTracker : IForegroundUsageTracker
{
    private readonly ILogger<ForegroundUsageTracker> _logger;
    private const int IdleThresholdSeconds = 120; // Pause app time after 2 minutes without input

    private static readonly string UsageDirectory = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "WRMS.Agent",
        "usage");

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    // OS shell overlays / lock screens / self that should not count as user business applications
    private static readonly HashSet<string> IgnoredExecutables = new(StringComparer.OrdinalIgnoreCase)
    {
        "idle.exe",
        "lockapp.exe",
        "logonui.exe",
        "shellexperiencehost.exe",
        "startmenuexperiencehost.exe",
        "searchhost.exe",
        "searchapp.exe",
        "textinputhost.exe",
        "applicationframehost.exe",
        "wrms.agent.exe"
    };

    private static readonly Dictionary<string, (string AppName, string Publisher)> KnownFriendlyApps = new(StringComparer.OrdinalIgnoreCase)
    {
        ["chrome.exe"] = ("Google Chrome", "Google LLC"),
        ["msedge.exe"] = ("Microsoft Edge", "Microsoft Corporation"),
        ["firefox.exe"] = ("Mozilla Firefox", "Mozilla Corporation"),
        ["brave.exe"] = ("Brave Browser", "Brave Software"),
        ["opera.exe"] = ("Opera Browser", "Opera Software"),
        ["antigravity ide.exe"] = ("Antigravity IDE", "Google"),
        ["code.exe"] = ("Visual Studio Code", "Microsoft Corporation"),
        ["devenv.exe"] = ("Microsoft Visual Studio", "Microsoft Corporation"),
        ["mongodbcompass.exe"] = ("MongoDB Compass", "MongoDB, Inc."),
        ["notepad++.exe"] = ("Notepad++", "Don Ho"),
        ["notepad.exe"] = ("Windows Notepad", "Microsoft Corporation"),
        ["calculatorapp.exe"] = ("Windows Calculator", "Microsoft Corporation"),
        ["calc.exe"] = ("Windows Calculator", "Microsoft Corporation"),
        ["screensketch.exe"] = ("Snipping Tool", "Microsoft Corporation"),
        ["windowsterminal.exe"] = ("Windows Terminal", "Microsoft Corporation"),
        ["wt.exe"] = ("Windows Terminal", "Microsoft Corporation"),
        ["powershell.exe"] = ("Windows PowerShell", "Microsoft Corporation"),
        ["pwsh.exe"] = ("PowerShell", "Microsoft Corporation"),
        ["cmd.exe"] = ("Command Prompt", "Microsoft Corporation"),
        ["explorer.exe"] = ("File Explorer", "Microsoft Corporation"),
        ["postman.exe"] = ("Postman", "Postman, Inc."),
        ["studio64.exe"] = ("Android Studio", "Google LLC"),
        ["studio.exe"] = ("Android Studio", "Google LLC"),
        ["ms-teams.exe"] = ("Microsoft Teams", "Microsoft Corporation"),
        ["winword.exe"] = ("Microsoft Word", "Microsoft Corporation"),
        ["excel.exe"] = ("Microsoft Excel", "Microsoft Corporation"),
        ["powerpnt.exe"] = ("Microsoft PowerPoint", "Microsoft Corporation"),
        ["outlook.exe"] = ("Microsoft Outlook", "Microsoft Corporation"),
        ["docker desktop.exe"] = ("Docker Desktop", "Docker Inc."),
        ["ssms.exe"] = ("SQL Server Management Studio", "Microsoft Corporation")
    };

    private readonly Dictionary<string, (string AppName, string Publisher)> _exeMetadataCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, (string AppName, string Publisher)> _registryExeMap = new(StringComparer.OrdinalIgnoreCase);
    private DateTime _lastRegistryIndexTime = DateTime.MinValue;
    private DateTime _lastGeoCaptureUtc = DateTime.MinValue;
    private readonly IGeoLocationService? _geoLocationService;

    // Tracks which GUI apps currently have at least one visible window so opening tabs doesn't count as relaunches
    private readonly HashSet<string> _currentlyOpenGuiExes = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _fileLock = new();

    public ForegroundUsageTracker(
        ILogger<ForegroundUsageTracker> logger,
        IGeoLocationService? geoLocationService = null)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _geoLocationService = geoLocationService;
    }

    public void EnsureStorageReady()
    {
        try
        {
            Directory.CreateDirectory(UsageDirectory);

            if (OperatingSystem.IsWindows())
            {
                // Allow the non-elevated interactive user session helper to update usage files inside ProgramData
                var dirInfo = new DirectoryInfo(UsageDirectory);
                var security = dirInfo.GetAccessControl();
                var authUsers = new SecurityIdentifier(WellKnownSidType.AuthenticatedUserSid, null);
                security.AddAccessRule(new FileSystemAccessRule(
                    authUsers,
                    FileSystemRights.Modify | FileSystemRights.Synchronize,
                    InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                    PropagationFlags.None,
                    AccessControlType.Allow));
                dirInfo.SetAccessControl(security);
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not adjust ACL on usage tracking directory {Dir}.", UsageDirectory);
        }
    }

    public DailyAppUsageSummary? ReadDailySummary(string? localDate = null)
    {
        var dateKey = string.IsNullOrWhiteSpace(localDate)
            ? DateTime.Now.ToString("yyyy-MM-dd")
            : localDate.Trim();

        var path = GetDailyFilePath(dateKey);
        if (!File.Exists(path))
        {
            return null;
        }

        lock (_fileLock)
        {
            try
            {
                var json = File.ReadAllText(path);
                return JsonSerializer.Deserialize<DailyAppUsageSummary>(json, JsonOptions);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to read daily usage summary from {Path}.", path);
                return null;
            }
        }
    }

    public async Task RunSessionLoopAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindows())
        {
            return;
        }

        EnsureStorageReady();
        RefreshRegistryExecutableIndexIfNeeded();

        var currentDate = DateTime.Now.ToString("yyyy-MM-dd");
        var summary = LoadOrCreateSummary(currentDate);
        var lastSaveUtc = DateTime.UtcNow;

        _logger.LogInformation("WRMS Foreground Usage Tracker started in user session for date {Date}.", currentDate);

        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        while (!cancellationToken.IsCancellationRequested && await timer.WaitForNextTickAsync(cancellationToken))
        {
            try
            {
                var nowLocal = DateTime.Now;
                var nowUtc = DateTime.UtcNow;
                var todayKey = nowLocal.ToString("yyyy-MM-dd");

                // Rollover cleanly at local midnight
                if (!string.Equals(todayKey, currentDate, StringComparison.Ordinal))
                {
                    PersistSummary(summary);
                    currentDate = todayKey;
                    summary = LoadOrCreateSummary(currentDate);
                    _currentlyOpenGuiExes.Clear();
                }

                // Periodically refresh installed registry lookup every 30 minutes
                RefreshRegistryExecutableIndexIfNeeded();

                // Refresh accurate Windows OS geolocation in background every 5 minutes inside user session
                if (_geoLocationService != null && (nowUtc - _lastGeoCaptureUtc).TotalMinutes >= 5)
                {
                    _lastGeoCaptureUtc = nowUtc;
                    _ = Task.Run(() => _geoLocationService.CaptureAndPersistUserSessionLocationAsync(cancellationToken), cancellationToken);
                }

                // Update real app open/close launch transitions across visible desktop windows
                UpdateOpenWindowLaunchTransitions(summary, nowUtc);

                // Check user keyboard/mouse idle duration in this session
                var idleSec = GetIdleTimeSeconds();
                if (idleSec >= IdleThresholdSeconds)
                {
                    summary.TotalIdleSeconds += 1;
                }
                else
                {
                    var fg = ResolveActiveForegroundApp();
                    if (fg.HasValue && !IgnoredExecutables.Contains(fg.Value.Executable))
                    {
                        var (exe, appName, publisher) = fg.Value;
                        var entry = summary.Apps.FirstOrDefault(a =>
                            string.Equals(a.Executable, exe, StringComparison.OrdinalIgnoreCase));

                        var nowIso = nowUtc.ToString("o");
                        if (entry == null)
                        {
                            entry = new DailyAppUsageEntry
                            {
                                Executable = exe,
                                AppName = appName,
                                Publisher = publisher,
                                ActiveSeconds = 1,
                                LaunchCount = 1,
                                FirstUsedAt = nowIso,
                                LastUsedAt = nowIso
                            };
                            summary.Apps.Add(entry);
                            _currentlyOpenGuiExes.Add(exe);
                        }
                        else
                        {
                            entry.ActiveSeconds += 1;
                            if (entry.LaunchCount <= 0)
                            {
                                entry.LaunchCount = 1;
                            }
                            if (string.IsNullOrEmpty(entry.FirstUsedAt))
                            {
                                entry.FirstUsedAt = nowIso;
                            }
                            entry.LastUsedAt = nowIso;

                            // Prefer richer friendly name if previously only exe name was known
                            if (!string.IsNullOrWhiteSpace(appName) && entry.AppName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                            {
                                entry.AppName = appName;
                            }
                        }

                        summary.TotalActiveSeconds += 1;
                    }
                }

                summary.LastUpdatedAt = nowUtc.ToString("o");

                if ((nowUtc - lastSaveUtc).TotalSeconds >= 5)
                {
                    PersistSummary(summary);
                    lastSaveUtc = nowUtc;
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Error in 1-second foreground tracking tick.");
            }
        }

        PersistSummary(summary);
    }

    private void UpdateOpenWindowLaunchTransitions(DailyAppUsageSummary summary, DateTime nowUtc)
    {
        var openThisTick = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var currentSessionId = Process.GetCurrentProcess().SessionId;

        foreach (var proc in Process.GetProcesses())
        {
            try
            {
                if (proc.SessionId != currentSessionId) continue;
                if (proc.MainWindowHandle == IntPtr.Zero) continue;

                var exe = ResolveExecutableFileName(proc);
                if (string.IsNullOrWhiteSpace(exe) || IgnoredExecutables.Contains(exe)) continue;

                openThisTick.Add(exe);

                // Only increment launchCount when transitioning from 0 open windows to >= 1 open window
                if (!_currentlyOpenGuiExes.Contains(exe))
                {
                    var (appName, publisher) = ResolveAppMetadata(exe, TryGetMainModulePath(proc));
                    var entry = summary.Apps.FirstOrDefault(a =>
                        string.Equals(a.Executable, exe, StringComparison.OrdinalIgnoreCase));

                    var nowIso = nowUtc.ToString("o");
                    if (entry == null)
                    {
                        summary.Apps.Add(new DailyAppUsageEntry
                        {
                            Executable = exe,
                            AppName = appName,
                            Publisher = publisher,
                            ActiveSeconds = 0,
                            LaunchCount = 1,
                            FirstUsedAt = nowIso,
                            LastUsedAt = nowIso
                        });
                    }
                    else
                    {
                        entry.LaunchCount += 1;
                        entry.LastUsedAt = nowIso;
                    }
                }
            }
            catch { }
            finally
            {
                proc.Dispose();
            }
        }

        _currentlyOpenGuiExes.Clear();
        foreach (var exe in openThisTick)
        {
            _currentlyOpenGuiExes.Add(exe);
        }
    }

    private (string Executable, string AppName, string Publisher)? ResolveActiveForegroundApp()
    {
        var hwnd = GetForegroundWindow();
        if (hwnd == IntPtr.Zero) return null;

        _ = GetWindowThreadProcessId(hwnd, out var pid);
        if (pid == 0) return null;

        Process? proc = null;
        try
        {
            proc = Process.GetProcessById((int)pid);

            // Unwrap UWP / Windows Store apps hosted inside ApplicationFrameHost.exe
            if (proc.ProcessName.Equals("ApplicationFrameHost", StringComparison.OrdinalIgnoreCase))
            {
                uint realChildPid = 0;
                EnumChildWindows(hwnd, (childHwnd, lParam) =>
                {
                    GetWindowThreadProcessId(childHwnd, out var childPid);
                    if (childPid != 0 && childPid != pid)
                    {
                        realChildPid = childPid;
                        return false; // Stop enumeration
                    }
                    return true;
                }, IntPtr.Zero);

                if (realChildPid != 0)
                {
                    proc.Dispose();
                    proc = Process.GetProcessById((int)realChildPid);
                }
            }

            var exe = ResolveExecutableFileName(proc);
            if (string.IsNullOrWhiteSpace(exe)) return null;

            var fullPath = TryGetMainModulePath(proc);
            var (appName, publisher) = ResolveAppMetadata(exe, fullPath);
            return (exe, appName, publisher);
        }
        catch
        {
            return null;
        }
        finally
        {
            proc?.Dispose();
        }
    }

    private static string ResolveExecutableFileName(Process proc)
    {
        var modulePath = TryGetMainModulePath(proc);
        if (!string.IsNullOrWhiteSpace(modulePath))
        {
            return Path.GetFileName(modulePath);
        }

        return string.IsNullOrWhiteSpace(proc.ProcessName) ? string.Empty : $"{proc.ProcessName}.exe";
    }

    private static string? TryGetMainModulePath(Process proc)
    {
        try
        {
            return proc.MainModule?.FileName;
        }
        catch
        {
            return null;
        }
    }

    private (string AppName, string Publisher) ResolveAppMetadata(string exe, string? fullPath)
    {
        if (KnownFriendlyApps.TryGetValue(exe, out var known))
        {
            return known;
        }

        if (_exeMetadataCache.TryGetValue(exe, out var cached))
        {
            return cached;
        }

        if (_registryExeMap.TryGetValue(exe, out var regMatch))
        {
            _exeMetadataCache[exe] = regMatch;
            return regMatch;
        }

        string appName = Path.GetFileNameWithoutExtension(exe);
        string publisher = "Unknown";

        if (!string.IsNullOrWhiteSpace(fullPath) && File.Exists(fullPath))
        {
            try
            {
                var info = FileVersionInfo.GetVersionInfo(fullPath);
                if (!string.IsNullOrWhiteSpace(info.FileDescription))
                {
                    appName = info.FileDescription.Trim();
                }
                else if (!string.IsNullOrWhiteSpace(info.ProductName))
                {
                    appName = info.ProductName.Trim();
                }

                if (!string.IsNullOrWhiteSpace(info.CompanyName))
                {
                    publisher = info.CompanyName.Trim();
                }
            }
            catch { }
        }

        var meta = (appName, publisher);
        _exeMetadataCache[exe] = meta;
        return meta;
    }

    private void RefreshRegistryExecutableIndexIfNeeded()
    {
        if ((DateTime.UtcNow - _lastRegistryIndexTime).TotalMinutes < 30)
        {
            return;
        }

        _lastRegistryIndexTime = DateTime.UtcNow;
        try
        {
            IndexUninstallHive(RegistryHive.LocalMachine, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
            IndexUninstallHive(RegistryHive.LocalMachine, RegistryView.Registry32, @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall");
            IndexUninstallHive(RegistryHive.CurrentUser, RegistryView.Registry64, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall");
        }
        catch { }
    }

    private void IndexUninstallHive(RegistryHive hive, RegistryView view, string subPath)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, view);
            using var root = baseKey.OpenSubKey(subPath);
            if (root == null) return;

            foreach (var sub in root.GetSubKeyNames())
            {
                try
                {
                    using var appKey = root.OpenSubKey(sub);
                    var displayName = appKey?.GetValue("DisplayName")?.ToString()?.Trim();
                    if (string.IsNullOrWhiteSpace(displayName)) continue;

                    var publisher = appKey?.GetValue("Publisher")?.ToString()?.Trim() ?? "Unknown";
                    var icon = appKey?.GetValue("DisplayIcon")?.ToString()?.Split(',')[0].Trim().Trim('"');
                    if (string.IsNullOrWhiteSpace(icon)) continue;

                    var exeIdx = icon.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
                    if (exeIdx > 0)
                    {
                        var exe = Path.GetFileName(icon.Substring(0, exeIdx + 4).Trim('"'));
                        if (!string.IsNullOrWhiteSpace(exe) &&
                            !exe.Contains("uninstall", StringComparison.OrdinalIgnoreCase) &&
                            !exe.Contains("setup", StringComparison.OrdinalIgnoreCase))
                        {
                            _registryExeMap.TryAdd(exe, (displayName, publisher));
                        }
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private DailyAppUsageSummary LoadOrCreateSummary(string dateKey)
    {
        var existing = ReadDailySummary(dateKey);
        if (existing != null)
        {
            existing.Apps ??= [];
            return existing;
        }

        return new DailyAppUsageSummary
        {
            Date = dateKey,
            TotalActiveSeconds = 0,
            TotalIdleSeconds = 0,
            LastUpdatedAt = DateTime.UtcNow.ToString("o"),
            Apps = []
        };
    }

    private void PersistSummary(DailyAppUsageSummary summary)
    {
        lock (_fileLock)
        {
            try
            {
                Directory.CreateDirectory(UsageDirectory);
                var target = GetDailyFilePath(summary.Date);
                var tmp = target + ".tmp";
                var json = JsonSerializer.Serialize(summary, JsonOptions);
                File.WriteAllText(tmp, json);
                File.Move(tmp, target, overwrite: true);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to persist daily usage summary for {Date}.", summary.Date);
            }
        }
    }

    private static string GetDailyFilePath(string dateKey)
    {
        var safeDate = new string(dateKey.Where(c => char.IsDigit(c) || c == '-').ToArray());
        return Path.Combine(UsageDirectory, $"{safeDate}.json");
    }

    private static uint GetIdleTimeSeconds()
    {
        var lii = new LASTINPUTINFO { cbSize = (uint)Marshal.SizeOf<LASTINPUTINFO>() };
        if (!GetLastInputInfo(ref lii))
        {
            return 0;
        }

        uint currentTick = unchecked((uint)Environment.TickCount);
        uint elapsedMs = unchecked(currentTick - lii.dwTime);
        return elapsedMs / 1000;
    }

    private delegate bool EnumWindowsProc(IntPtr hWnd, IntPtr lParam);

    [StructLayout(LayoutKind.Sequential)]
    private struct LASTINPUTINFO
    {
        public uint cbSize;
        public uint dwTime;
    }

    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool EnumChildWindows(IntPtr hwndParent, EnumWindowsProc lpEnumFunc, IntPtr lParam);

    [DllImport("user32.dll")]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetLastInputInfo(ref LASTINPUTINFO plii);
}
