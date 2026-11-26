namespace WRMS.Agent.Services;

using System.Collections.Concurrent;
using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using WRMS.Agent.Models;

/// <summary>
/// Hardware-independent software inventory harvester.
/// Enumerates 64-bit and 32-bit (WoW64) uninstall keys and correlates launch telemetry
/// using exact executable matching (no substring guesswork).
/// </summary>
public sealed class SoftwareInventoryService : ISoftwareInventoryService
{
    private readonly ILogger<SoftwareInventoryService> _logger;
    private readonly IForegroundUsageTracker _usageTracker;

    private const string UninstallSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall";
    private const string Wow64UninstallSubKey = @"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall";

    public SoftwareInventoryService(
        ILogger<SoftwareInventoryService> logger,
        IForegroundUsageTracker usageTracker)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _usageTracker = usageTracker ?? throw new ArgumentNullException(nameof(usageTracker));
    }

    public List<InstalledSoftwareInfo> GetInstalledSoftware()
    {
        var result = new Dictionary<string, InstalledSoftwareInfo>(StringComparer.OrdinalIgnoreCase);

        if (!OperatingSystem.IsWindows())
        {
            return result.Values.ToList();
        }

        try
        {
            var dailyUsage = _usageTracker.ReadDailySummary();
            var userAssistCounts = HarvestUserAssistCounts();

            // 1. Scan 64-bit HKLM
            ScanRegistryHives(RegistryHive.LocalMachine, RegistryView.Registry64, UninstallSubKey, result, dailyUsage, userAssistCounts);

            // 2. Scan 32-bit HKLM (WoW6432Node)
            ScanRegistryHives(RegistryHive.LocalMachine, RegistryView.Registry32, Wow64UninstallSubKey, result, dailyUsage, userAssistCounts);

            // 3. Scan User Hives under HKEY_USERS
            ScanUserHives(result, dailyUsage, userAssistCounts);

            var frequentlyUsed = result.Values.Where(s => s.ExecutionCount > 0).OrderByDescending(s => s.ExecutionCount).ToList();
            Console.WriteLine($"[DEBUG-SOFTWARE] GetInstalledSoftware() completed: {result.Count} installed apps ({frequentlyUsed.Count} launched today/UserAssist).");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Error scanning software inventory from registry.");
            Console.WriteLine($"[DEBUG-SOFTWARE] Error scanning software inventory: {ex.Message}");
        }

        return result.Values.OrderBy(s => s.Name).ToList();
    }

    private void ScanRegistryHives(
        RegistryHive hive,
        RegistryView view,
        string subKeyPath,
        Dictionary<string, InstalledSoftwareInfo> dict,
        DailyAppUsageSummary? dailyUsage,
        Dictionary<string, int> userAssistCounts)
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, view);
            using var uninstallKey = baseKey.OpenSubKey(subKeyPath);
            if (uninstallKey == null) return;

            foreach (var subName in uninstallKey.GetSubKeyNames())
            {
                try
                {
                    using var appKey = uninstallKey.OpenSubKey(subName);
                    if (appKey == null) continue;

                    var name = appKey.GetValue("DisplayName")?.ToString()?.Trim();
                    if (string.IsNullOrWhiteSpace(name)) continue;

                    // Skip Windows updates and internal hotfixes
                    var isSystemComp = appKey.GetValue("SystemComponent");
                    if (isSystemComp is int intSys && intSys == 1) continue;
                    var parentKey = appKey.GetValue("ParentKeyName")?.ToString();
                    if (!string.IsNullOrEmpty(parentKey)) continue;

                    var version = appKey.GetValue("DisplayVersion")?.ToString()?.Trim() ?? "1.0.0";
                    var publisher = appKey.GetValue("Publisher")?.ToString()?.Trim() ?? "Unknown";
                    var date = appKey.GetValue("InstallDate")?.ToString()?.Trim() ?? "";
                    var installLoc = appKey.GetValue("InstallLocation")?.ToString()?.Trim() ?? "";

                    // Attempt to deduce main executable name
                    var exe = DeduceExecutable(name, installLoc, appKey.GetValue("DisplayIcon")?.ToString());
                    int execCount = ResolveExactExecutionCount(name, exe, dailyUsage, userAssistCounts);

                    if (!dict.ContainsKey(name))
                    {
                        dict[name] = new InstalledSoftwareInfo
                        {
                            Name = name,
                            Executable = exe,
                            Publisher = publisher,
                            Version = version,
                            InstallDate = date,
                            ExecutionCount = execCount
                        };
                    }
                }
                catch { }
            }
        }
        catch { }
    }

    private void ScanUserHives(
        Dictionary<string, InstalledSoftwareInfo> dict,
        DailyAppUsageSummary? dailyUsage,
        Dictionary<string, int> userAssistCounts)
    {
        try
        {
            using var usersKey = Registry.Users;
            foreach (var sid in usersKey.GetSubKeyNames())
            {
                if (sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) &&
                    !sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        var path = $@"{sid}\Software\Microsoft\Windows\CurrentVersion\Uninstall";
                        using var uKey = usersKey.OpenSubKey(path);
                        if (uKey == null) continue;

                        foreach (var subName in uKey.GetSubKeyNames())
                        {
                            using var appKey = uKey.OpenSubKey(subName);
                            var name = appKey?.GetValue("DisplayName")?.ToString()?.Trim();
                            if (string.IsNullOrWhiteSpace(name)) continue;

                            var version = appKey?.GetValue("DisplayVersion")?.ToString()?.Trim() ?? "1.0.0";
                            var publisher = appKey?.GetValue("Publisher")?.ToString()?.Trim() ?? "Unknown";
                            var exe = DeduceExecutable(name, "", appKey?.GetValue("DisplayIcon")?.ToString());

                            int execCount = ResolveExactExecutionCount(name, exe, dailyUsage, userAssistCounts);

                            if (!dict.ContainsKey(name))
                            {
                                dict[name] = new InstalledSoftwareInfo
                                {
                                    Name = name,
                                    Executable = exe,
                                    Publisher = publisher,
                                    Version = version,
                                    ExecutionCount = execCount
                                };
                            }
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
    }

    private static readonly HashSet<string> GenericTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "Microsoft", "Google", "Adobe", "Oracle", "Apple", "Intel", "NVIDIA", "Mozilla",
        "Corporation", "Software", "Windows", "System", "Setup", "Installer", "Update",
        "Redistributable", "Version", "Service", "Framework", "Component", "Client",
        "Package", "Tools", "Runtime", "Desktop", "Edition", "Database", "Security"
    };

    public void RefreshExecutionCounts(List<InstalledSoftwareInfo> softwareList, DailyAppUsageSummary? dailyUsage = null)
    {
        if (softwareList == null || softwareList.Count == 0) return;
        try
        {
            dailyUsage ??= _usageTracker.ReadDailySummary();
            var userAssistCounts = HarvestUserAssistCounts();

            foreach (var app in softwareList)
            {
                app.ExecutionCount = ResolveExactExecutionCount(app.Name, app.Executable, dailyUsage, userAssistCounts);
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[DEBUG-SOFTWARE] Error in RefreshExecutionCounts: {ex.Message}");
        }
    }

    private Dictionary<string, int> HarvestUserAssistCounts()
    {
        var counts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

        void AddCount(string? token, int count)
        {
            if (string.IsNullOrWhiteSpace(token) || token.Length < 2) return;
            token = token.Trim();
            if (!counts.TryGetValue(token, out var existing) || count > existing)
            {
                counts[token] = count;
            }

            var alpha = new string(token.Where(char.IsLetterOrDigit).ToArray());
            if (!string.IsNullOrWhiteSpace(alpha) && alpha.Length >= 2 && (!counts.TryGetValue(alpha, out var exAlpha) || count > exAlpha))
            {
                counts[alpha] = count;
            }
        }

        void ScanKey(RegistryKey? userAssistBase)
        {
            if (userAssistBase == null) return;
            try
            {
                foreach (var guid in userAssistBase.GetSubKeyNames())
                {
                    try
                    {
                        using var countKey = userAssistBase.OpenSubKey($@"{guid}\Count");
                        if (countKey == null) continue;

                        foreach (var valName in countKey.GetValueNames())
                        {
                            try
                            {
                                if (valName.StartsWith("UEME_", StringComparison.OrdinalIgnoreCase)) continue;

                                if (countKey.GetValue(valName) is byte[] rawBytes && rawBytes.Length >= 8)
                                {
                                    int runCount = BitConverter.ToInt32(rawBytes, 4);
                                    if (runCount <= 0) continue;

                                    var decoded = DecodeRot13(valName);
                                    if (string.IsNullOrWhiteSpace(decoded) || decoded.StartsWith("UEME_", StringComparison.OrdinalIgnoreCase)) continue;

                                    // 1. Raw decoded token
                                    AddCount(decoded, runCount);

                                    // 2. If it's a file path or contains directory separators
                                    if (decoded.Contains('\\') || decoded.Contains('/'))
                                    {
                                        var fileName = Path.GetFileName(decoded);
                                        AddCount(fileName, runCount);
                                        AddCount(Path.GetFileNameWithoutExtension(fileName), runCount);
                                    }
                                    else if (decoded.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                                    {
                                        AddCount(decoded, runCount);
                                        AddCount(Path.GetFileNameWithoutExtension(decoded), runCount);
                                    }

                                    // 3. If it's a UWP / Packaged app (e.g. Microsoft.WindowsNotepad_8wekyb3d8bbwe!App)
                                    if (decoded.Contains('!'))
                                    {
                                        var parts = decoded.Split('!');
                                        foreach (var part in parts)
                                        {
                                            AddCount(part, runCount);
                                            var subParts = part.Split(new[] { '.', '_', '-' }, StringSplitOptions.RemoveEmptyEntries);
                                            foreach (var sp in subParts)
                                            {
                                                if (sp.Length >= 3 && !sp.All(char.IsDigit) && !sp.StartsWith("8wek", StringComparison.OrdinalIgnoreCase) && !GenericTokens.Contains(sp))
                                                {
                                                    AddCount(sp, runCount);
                                                }
                                            }
                                        }
                                    }

                                    // 4. Dot-separated package names (e.g. Google.AntigravityIDE, VisualStudio.a6860125, com.squirrel.MongoDBCompass)
                                    var segments = decoded.Split(new[] { '.', '_', '-' }, StringSplitOptions.RemoveEmptyEntries);
                                    foreach (var seg in segments)
                                    {
                                        if (seg.Length >= 3 && !seg.All(char.IsDigit) && !GenericTokens.Contains(seg))
                                        {
                                            AddCount(seg, runCount);
                                        }
                                    }
                                }
                            }
                            catch { }
                        }
                    }
                    catch { }
                }
            }
            catch { }
        }

        try
        {
            // Scan current user (or System HKCU)
            using var cuKey = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
            ScanKey(cuKey);

            // Scan all interactive user profiles under HKEY_USERS
            using var usersKey = Registry.Users;
            string[] subKeys = [];
            try { subKeys = usersKey.GetSubKeyNames(); } catch { }

            foreach (var sid in subKeys)
            {
                if (sid.StartsWith("S-1-5-21-", StringComparison.OrdinalIgnoreCase) && !sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase))
                {
                    try
                    {
                        using var uKey = usersKey.OpenSubKey($@"{sid}\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist");
                        ScanKey(uKey);
                    }
                    catch { }
                }
            }

            Console.WriteLine($"[DEBUG-SOFTWARE] HarvestUserAssistCounts() -> {counts.Count} execution count tokens extracted from UserAssist.");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[DEBUG-SOFTWARE] HarvestUserAssistCounts error: {ex.Message}");
        }

        return counts;
    }

    private static int ResolveExactExecutionCount(
        string appName,
        string exe,
        DailyAppUsageSummary? dailyUsage,
        Dictionary<string, int> userAssistCounts)
    {
        int count = 0;

        // 1. Exact executable match from real daily foreground tracker (preferred, accurate)
        if (dailyUsage?.Apps != null && !string.IsNullOrWhiteSpace(exe))
        {
            var tracked = dailyUsage.Apps.FirstOrDefault(a =>
                string.Equals(a.Executable, exe, StringComparison.OrdinalIgnoreCase));
            if (tracked != null && tracked.LaunchCount > 0)
            {
                count = Math.Max(count, tracked.LaunchCount);
            }
        }

        // 2. Exact executable / exact app name match from Windows UserAssist (never loose substring matching)
        var baseExe = !string.IsNullOrWhiteSpace(exe) ? Path.GetFileNameWithoutExtension(exe) : string.Empty;
        if (!string.IsNullOrWhiteSpace(exe) && userAssistCounts.TryGetValue(exe, out var uaExeCount))
        {
            count = Math.Max(count, uaExeCount);
        }
        if (!string.IsNullOrWhiteSpace(baseExe) &&
            !GenericTokens.Contains(baseExe) &&
            userAssistCounts.TryGetValue(baseExe, out var uaBaseCount))
        {
            count = Math.Max(count, uaBaseCount);
        }
        if (!string.IsNullOrWhiteSpace(appName) && userAssistCounts.TryGetValue(appName, out var uaAppCount))
        {
            count = Math.Max(count, uaAppCount);
        }

        return count;
    }

    private static string DecodeRot13(string input)
    {
        if (string.IsNullOrEmpty(input)) return input;
        var chars = input.ToCharArray();
        for (int i = 0; i < chars.Length; i++)
        {
            char c = chars[i];
            if (c >= 'a' && c <= 'z')
                chars[i] = (char)((c - 'a' + 13) % 26 + 'a');
            else if (c >= 'A' && c <= 'Z')
                chars[i] = (char)((c - 'A' + 13) % 26 + 'A');
        }
        return new string(chars);
    }

    private static string DeduceExecutable(string appName, string installLocation, string? displayIcon)
    {
        // Common well-known application aliases (checked before Installer/Setup DisplayIcon fallbacks)
        var lower = appName.ToLowerInvariant();
        if (lower.Contains("chrome")) return "chrome.exe";
        if (lower.Contains("edge")) return "msedge.exe";
        if (lower.Contains("firefox")) return "firefox.exe";
        if (lower.Contains("antigravity")) return "Antigravity IDE.exe";
        if (lower.Contains("visual studio code") || lower.Contains("vs code")) return "Code.exe";
        if (lower.Contains("visual studio") && !lower.Contains("installer") && !lower.Contains(".net sdk")) return "devenv.exe";
        if (lower.Contains("postman")) return "Postman.exe";
        if (lower.Contains("notepad++")) return "notepad++.exe";
        if (lower.Equals("git", StringComparison.OrdinalIgnoreCase)) return "git.exe";
        if (lower.Equals("node.js", StringComparison.OrdinalIgnoreCase)) return "node.exe";
        if (lower.Contains("docker desktop")) return "Docker Desktop.exe";
        if (lower.Contains("mongodb compass")) return "MongoDBCompass.exe";
        if (lower.Equals("photos", StringComparison.OrdinalIgnoreCase)) return "Microsoft.Photos.exe";

        if (!string.IsNullOrWhiteSpace(displayIcon))
        {
            var cleanIcon = displayIcon.Split(',')[0].Trim().Trim('"');
            var exeIdx = cleanIcon.IndexOf(".exe", StringComparison.OrdinalIgnoreCase);
            if (exeIdx > 0)
            {
                var exePath = cleanIcon.Substring(0, exeIdx + 4).Trim('"');
                return Path.GetFileName(exePath);
            }
            if (cleanIcon.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            {
                return Path.GetFileName(cleanIcon);
            }
        }

        var clean = appName.ToLowerInvariant().Replace(" ", "");
        var exes = new[] { $"{clean}.exe", $"{Path.GetFileNameWithoutExtension(clean)}.exe" };
        return exes[0];
    }
}
