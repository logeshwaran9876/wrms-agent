namespace WRMS.Agent.Services;

using System.Diagnostics;
using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using WRMS.Agent.Constants;
using WRMS.Agent.Models;
using WRMS.Agent.Windows;

/// <summary>
/// Bulletproof enterprise application execution restriction engine for Windows endpoints.
/// Combines 3 complementary layers of Windows security enforcement:
/// 1. Native Windows Explorer DisallowRun Group Policy
/// 2. Image File Execution Options (IFEO) kernel-level execution interceptor
/// 3. High-frequency active process watchdog & terminator (1-second cycle)
/// </summary>
public sealed class ApplicationPolicyService : IApplicationPolicyService, IDisposable
{
    private readonly ILogger<ApplicationPolicyService> _logger;
    private readonly IWindowsRegistryService _registryService;
    private readonly HashSet<string> _activeBlockedExecutables = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _activeBlockedProcessNames = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _lock = new();
    private readonly CancellationTokenSource _cts = new();

    private const string IfeoRootSubKey = @"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options";

    public ApplicationPolicyService(
        ILogger<ApplicationPolicyService> logger,
        IWindowsRegistryService registryService)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _registryService = registryService ?? throw new ArgumentNullException(nameof(registryService));

        // Start real-time background process watchdog (runs every 1 second)
        _ = Task.Run(RunWatchdogLoopAsync);
    }

    public async Task<(bool Success, List<PolicyRuleResult> Rules, List<string> Errors)> ApplyAsync(
        IReadOnlyList<ApplicationRule> rules,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var ruleResults = new List<PolicyRuleResult>();
        var errors = new List<string>();

        var blockedRules = rules.Where(r => r.Block).ToList();
        var blockedExes = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var blockedProcNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rule in blockedRules)
        {
            var raw = string.IsNullOrWhiteSpace(rule.ExecutableName) ? rule.AppName : rule.ExecutableName;
            var clean = NormalizeExecutable(raw);
            if (!string.IsNullOrEmpty(clean))
            {
                // Expand aliases (e.g. calc.exe -> calc.exe, CalculatorApp.exe, Calculator.exe)
                foreach (var alias in ExpandExecutableAliases(clean))
                {
                    blockedExes.Add(alias);
                    var procName = Path.GetFileNameWithoutExtension(alias);
                    if (!string.IsNullOrEmpty(procName))
                    {
                        blockedProcNames.Add(procName);
                    }
                }
            }
        }

        // Update in-memory active list for real-time watchdog
        lock (_lock)
        {
            _activeBlockedExecutables.Clear();
            _activeBlockedProcessNames.Clear();
            foreach (var exe in blockedExes) _activeBlockedExecutables.Add(exe);
            foreach (var proc in blockedProcNames) _activeBlockedProcessNames.Add(proc);
        }

        _logger.LogInformation("Applying application control: {Count} executable targets blocked ({Exes})...",
            blockedExes.Count, string.Join(", ", blockedExes));

        try
        {
            if (blockedExes.Count > 0)
            {
                // Layer 1: Windows Explorer DisallowRun in HKLM, HKCU, and across ALL interactive user sessions in HKEY_USERS
                await ApplyDisallowRunRegistryAsync(RegistryHive.LocalMachine, blockedExes, cancellationToken);
                await ApplyDisallowRunRegistryAsync(RegistryHive.CurrentUser, blockedExes, cancellationToken);
                ApplyDisallowRunToAllUserSids(blockedExes);

                // Layer 2: Image File Execution Options (IFEO) interception (both 64-bit and 32-bit WoW64)
                await ApplyIfeoRegistryAsync(blockedExes, cancellationToken);
                RemoveStaleManagedIfeoKeys(blockedExes);

                // Layer 3: Immediately terminate any active instances of the blocked apps
                await TerminateBlockedProcessesAsync(cancellationToken);

                ruleResults.Add(PolicyRuleResult.Succeeded(
                    "ApplicationControl",
                    $"{blockedExes.Count} Executables",
                    $"Triple-layer block active (DisallowRun + IFEO + Watchdog) for: {string.Join(", ", blockedExes)}"));
            }
            else
            {
                // No applications blocked -> clean up all restriction layers
                await RemoveDisallowRunRegistryAsync(RegistryHive.LocalMachine, cancellationToken);
                await RemoveDisallowRunRegistryAsync(RegistryHive.CurrentUser, cancellationToken);
                RemoveDisallowRunFromAllUserSids();
                await RemoveAllManagedIfeoAsync(cancellationToken);

                ruleResults.Add(PolicyRuleResult.Succeeded(
                    "ApplicationControl",
                    "All Applications",
                    "No applications restricted. All DisallowRun and IFEO policies cleared."));
            }

            return (true, ruleResults, errors);
        }
        catch (Exception ex)
        {
            var msg = $"Failed applying application control policies: {ex.Message}";
            _logger.LogError(ex, msg);
            errors.Add(msg);
            ruleResults.Add(PolicyRuleResult.Failed("ApplicationControl", "DisallowRun/IFEO", msg));
            return (false, ruleResults, errors);
        }
    }

    public async Task<(bool Success, List<PolicyRuleResult> Rules, List<string> Errors)> RemoveAsync(
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var ruleResults = new List<PolicyRuleResult>();
        var errors = new List<string>();

        lock (_lock)
        {
            _activeBlockedExecutables.Clear();
            _activeBlockedProcessNames.Clear();
        }

        try
        {
            await RemoveDisallowRunRegistryAsync(RegistryHive.LocalMachine, cancellationToken);
            await RemoveDisallowRunRegistryAsync(RegistryHive.CurrentUser, cancellationToken);
            RemoveDisallowRunFromAllUserSids();
            await RemoveAllManagedIfeoAsync(cancellationToken);

            ruleResults.Add(PolicyRuleResult.Succeeded(
                "ApplicationControl",
                "All",
                "Application restrictions removed successfully."));

            return (true, ruleResults, errors);
        }
        catch (Exception ex)
        {
            var msg = $"Error reverting application policies: {ex.Message}";
            _logger.LogError(ex, msg);
            errors.Add(msg);
            return (false, ruleResults, errors);
        }
    }

    public Task TerminateBlockedProcessesAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        List<string> targetProcNames;
        lock (_lock)
        {
            targetProcNames = [.. _activeBlockedProcessNames];
        }

        if (targetProcNames.Count == 0) return Task.CompletedTask;

        foreach (var procName in targetProcNames)
        {
            try
            {
                var running = Process.GetProcessesByName(procName);
                foreach (var proc in running)
                {
                    try
                    {
                        var pid = proc.Id;
                        proc.Kill(entireProcessTree: true);
                        _logger.LogWarning(
                            "[SECURITY WATCHDOG] Blocked application '{ProcessName}.exe' (PID: {Pid}) was detected and terminated.",
                            procName, pid);
                    }
                    catch
                    {
                        // Ignore already exited process
                    }
                    finally
                    {
                        proc.Dispose();
                    }
                }
            }
            catch
            {
                // Ignore process scan errors
            }
        }

        return Task.CompletedTask;
    }

    private async Task RunWatchdogLoopAsync()
    {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                if (await timer.WaitForNextTickAsync(_cts.Token))
                {
                    await TerminateBlockedProcessesAsync(_cts.Token);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch
            {
                // Continue loop
            }
        }
    }

    private async Task ApplyDisallowRunRegistryAsync(
        RegistryHive hive,
        IEnumerable<string> blockedExes,
        CancellationToken cancellationToken)
    {
        await _registryService.SetDWordValueAsync(
            hive,
            PolicyConstants.Registry.ExplorerPoliciesSubKey,
            PolicyConstants.Registry.DisallowRunValueName,
            1,
            cancellationToken);

        if (await _registryService.SubKeyExistsAsync(hive, PolicyConstants.Registry.DisallowRunSubKey, cancellationToken))
        {
            await _registryService.DeleteSubKeyTreeAsync(hive, PolicyConstants.Registry.DisallowRunSubKey, cancellationToken);
        }

        var index = 1;
        foreach (var exe in blockedExes)
        {
            await _registryService.SetStringValueAsync(
                hive,
                PolicyConstants.Registry.DisallowRunSubKey,
                index.ToString(),
                exe,
                cancellationToken);
            index++;
        }

        await _registryService.SetDWordValueAsync(
            hive,
            PolicyConstants.Registry.DisallowRunSubKey,
            PolicyConstants.Registry.WrmsOwnershipTagValueName,
            PolicyConstants.Registry.WrmsOwnershipValue,
            cancellationToken);
    }

    private async Task RemoveDisallowRunRegistryAsync(RegistryHive hive, CancellationToken cancellationToken)
    {
        var isManaged = await _registryService.ValueExistsAsync(
            hive,
            PolicyConstants.Registry.DisallowRunSubKey,
            PolicyConstants.Registry.WrmsOwnershipTagValueName,
            cancellationToken);

        if (isManaged)
        {
            await _registryService.DeleteSubKeyTreeAsync(hive, PolicyConstants.Registry.DisallowRunSubKey, cancellationToken);
            await _registryService.DeleteValueAsync(
                hive,
                PolicyConstants.Registry.ExplorerPoliciesSubKey,
                PolicyConstants.Registry.DisallowRunValueName,
                cancellationToken);
        }
    }

    private void ApplyDisallowRunToAllUserSids(IEnumerable<string> blockedExes)
    {
        if (!OperatingSystem.IsWindows()) return;
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
                        using var expKey = usersKey.CreateSubKey($@"{sid}\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer");
                        expKey?.SetValue("DisallowRun", 1, RegistryValueKind.DWord);

                        var disallowPath = $@"{sid}\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun";
                        try { usersKey.DeleteSubKeyTree(disallowPath, throwOnMissingSubKey: false); } catch { }

                        using var disallowKey = usersKey.CreateSubKey(disallowPath);
                        if (disallowKey != null)
                        {
                            var idx = 1;
                            foreach (var exe in blockedExes)
                            {
                                disallowKey.SetValue(idx.ToString(), exe, RegistryValueKind.String);
                                idx++;
                            }
                            disallowKey.SetValue(
                                PolicyConstants.Registry.WrmsOwnershipTagValueName,
                                PolicyConstants.Registry.WrmsOwnershipValue,
                                RegistryValueKind.DWord);
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
    }

    private void RemoveDisallowRunFromAllUserSids()
    {
        if (!OperatingSystem.IsWindows()) return;
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
                        var disallowPath = $@"{sid}\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun";
                        using var chk = usersKey.OpenSubKey(disallowPath);
                        if (chk?.GetValue(PolicyConstants.Registry.WrmsOwnershipTagValueName) != null)
                        {
                            usersKey.DeleteSubKeyTree(disallowPath, throwOnMissingSubKey: false);
                            using var expKey = usersKey.OpenSubKey($@"{sid}\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", writable: true);
                            expKey?.DeleteValue("DisallowRun", throwOnMissingValue: false);
                        }
                    }
                    catch { }
                }
            }
        }
        catch { }
    }

    private async Task ApplyIfeoRegistryAsync(IEnumerable<string> blockedExes, CancellationToken cancellationToken)
    {
        foreach (var exe in blockedExes)
        {
            var ifeoKey = $@"{IfeoRootSubKey}\{exe}";
            var ifeo32Key = $@"SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{exe}";

            // 64-bit IFEO
            await _registryService.SetStringValueAsync(
                RegistryHive.LocalMachine,
                ifeoKey,
                "Debugger",
                "systray.exe",
                cancellationToken);

            await _registryService.SetDWordValueAsync(
                RegistryHive.LocalMachine,
                ifeoKey,
                PolicyConstants.Registry.WrmsOwnershipTagValueName,
                PolicyConstants.Registry.WrmsOwnershipValue,
                cancellationToken);

            // 32-bit IFEO (WoW6432Node)
            await _registryService.SetStringValueAsync(
                RegistryHive.LocalMachine,
                ifeo32Key,
                "Debugger",
                "systray.exe",
                cancellationToken);

            await _registryService.SetDWordValueAsync(
                RegistryHive.LocalMachine,
                ifeo32Key,
                PolicyConstants.Registry.WrmsOwnershipTagValueName,
                PolicyConstants.Registry.WrmsOwnershipValue,
                cancellationToken);
        }
    }

    private Task RemoveAllManagedIfeoAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        RemoveStaleManagedIfeoKeys([]);
        return Task.CompletedTask;
    }

    /// <summary>
    /// Enumerates 64-bit and 32-bit IFEO keys and deletes any WRMS-managed entries not currently blocked.
    /// </summary>
    private void RemoveStaleManagedIfeoKeys(IReadOnlyCollection<string> keepBlockedExes)
    {
        if (!OperatingSystem.IsWindows()) return;

        var keepSet = new HashSet<string>(keepBlockedExes, StringComparer.OrdinalIgnoreCase);

        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var ifeoRoot = baseKey.OpenSubKey(IfeoRootSubKey, writable: true);
                if (ifeoRoot == null) continue;

                foreach (var exeSubKeyName in ifeoRoot.GetSubKeyNames())
                {
                    if (keepSet.Contains(exeSubKeyName)) continue;

                    try
                    {
                        using var sub = ifeoRoot.OpenSubKey(exeSubKeyName, writable: false);
                        if (sub == null) continue;

                        var managed = sub.GetValue(PolicyConstants.Registry.WrmsOwnershipTagValueName);
                        bool isManaged = managed != null && int.TryParse(managed.ToString(), out var m) && m == PolicyConstants.Registry.WrmsOwnershipValue;
                        if (isManaged)
                        {
                            ifeoRoot.DeleteSubKeyTree(exeSubKeyName, throwOnMissingSubKey: false);
                            _logger.LogInformation("Removed stale WRMS IFEO restriction ({View}): {Exe}", view, exeSubKeyName);
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogDebug(ex, "Could not clean IFEO key {Exe} ({View}).", exeSubKeyName, view);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to enumerate IFEO root for {View}.", view);
            }
        }
    }

    private static IEnumerable<string> ExpandExecutableAliases(string exe)
    {
        yield return exe;

        var nameWithoutExt = Path.GetFileNameWithoutExtension(exe).ToLowerInvariant();
        if (nameWithoutExt is "calc" or "calculator" or "calculatorapp")
        {
            yield return "calc.exe";
            yield return "CalculatorApp.exe";
            yield return "Calculator.exe";
        }
        else if (nameWithoutExt is "notepad")
        {
            yield return "notepad.exe";
        }
        else if (nameWithoutExt is "cmd")
        {
            yield return "cmd.exe";
        }
        else if (nameWithoutExt is "powershell" or "pwsh")
        {
            yield return "powershell.exe";
            yield return "pwsh.exe";
        }
        else if (nameWithoutExt is "discord")
        {
            yield return "discord.exe";
        }
        else if (nameWithoutExt is "steam")
        {
            yield return "steam.exe";
        }
        else if (nameWithoutExt is "spotify")
        {
            yield return "spotify.exe";
        }
    }

    private static string NormalizeExecutable(string input)
    {
        if (string.IsNullOrWhiteSpace(input)) return string.Empty;
        var str = input.Trim().ToLowerInvariant();
        str = Path.GetFileName(str);
        if (!string.IsNullOrEmpty(str) && !str.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
        {
            str += ".exe";
        }
        return str;
    }

    public void Dispose()
    {
        _cts.Cancel();
        _cts.Dispose();
    }
}
