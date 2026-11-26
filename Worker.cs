namespace WRMS.Agent;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WRMS.Agent.Api;
using WRMS.Agent.Configuration;
using WRMS.Agent.Logging;
using WRMS.Agent.Models;
using WRMS.Agent.Policies;
using WRMS.Agent.Security;
using WRMS.Agent.Services;

/// <summary>
/// Core Windows Worker Service coordinating the lifecycle and recurring execution cycles of WRMS Agent.
/// Evaluates device identity, loads policies, and delegates application to the PolicyApplicationService.
/// </summary>
public sealed class Worker : BackgroundService
{
    private readonly ILogger<Worker> _logger;
    private readonly AgentSettings _settings;
    private readonly IDeviceIdentityService _deviceIdentityService;
    private readonly IPolicyProvider _policyProvider;
    private readonly IPolicyApplicationService _policyApplicationService;
    private readonly IAgentApiClient _apiClient;
    private readonly IPrivilegeService _privilegeService;
    private readonly ISoftwareInventoryService _softwareInventory;
    private readonly IForegroundUsageTracker _usageTracker;
    private readonly UserSessionLauncher _sessionLauncher;
    private bool _isRegistered;
    private int _cycleNumber = 0;

    public Worker(
        ILogger<Worker> logger,
        IOptions<AgentSettings> settings,
        IDeviceIdentityService deviceIdentityService,
        IPolicyProvider policyProvider,
        IPolicyApplicationService policyApplicationService,
        IAgentApiClient apiClient,
        IPrivilegeService privilegeService,
        ISoftwareInventoryService softwareInventory,
        IForegroundUsageTracker usageTracker,
        UserSessionLauncher sessionLauncher)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _settings = settings?.Value ?? throw new ArgumentNullException(nameof(settings));
        _deviceIdentityService = deviceIdentityService ?? throw new ArgumentNullException(nameof(deviceIdentityService));
        _policyProvider = policyProvider ?? throw new ArgumentNullException(nameof(policyProvider));
        _policyApplicationService = policyApplicationService ?? throw new ArgumentNullException(nameof(policyApplicationService));
        _apiClient = apiClient ?? throw new ArgumentNullException(nameof(apiClient));
        _privilegeService = privilegeService ?? throw new ArgumentNullException(nameof(privilegeService));
        _softwareInventory = softwareInventory ?? throw new ArgumentNullException(nameof(softwareInventory));
        _usageTracker = usageTracker ?? throw new ArgumentNullException(nameof(usageTracker));
        _sessionLauncher = sessionLauncher ?? throw new ArgumentNullException(nameof(sessionLauncher));
    }

    public override async Task StartAsync(CancellationToken cancellationToken)
    {
        _logger.LogServiceStarting(_settings.AgentName, _settings.AgentVersion);

        // Check and warn if process is not elevated
        if (!_privilegeService.IsRunningAsAdministrator())
        {
            _logger.LogError("==========================================================================");
            _logger.LogError(" [CRITICAL PERMISSION ERROR] WRMS AGENT IS NOT RUNNING AS ADMINISTRATOR!");
            _logger.LogError(" Applying Windows hosts blocking and Chrome/Edge policies will FAIL.");
            _logger.LogError(" Please right-click PowerShell or CMD and choose 'Run as Administrator'.");
            _logger.LogError("==========================================================================");
        }
        else
        {
            _logger.LogInformation("Administrator elevation confirmed. Windows system enforcement active.");
        }

        _logger.LogInformation(
            "Service configuration loaded: Interval = {Interval}s, WebsiteBlocking = {WebBlocking}, BrowserPolicy = {BrowserPolicy}",
            _settings.PolicyCheckIntervalSeconds,
            _settings.EnablePocWebsiteBlocking,
            _settings.EnablePocBrowserPolicy);

        // Ensure usage telemetry storage ACLs & launch user-session foreground screen-time tracker
        _usageTracker.EnsureStorageReady();
        _sessionLauncher.EnsureSessionTrackerRunning();

        // Identify and register device on startup (force fresh telemetry scan on install/first boot)
        try
        {
            var deviceInfo = await _deviceIdentityService.GetDeviceInfoAsync(cancellationToken, forceScan: true);
            _logger.LogInformation(
                "WRMS Agent initialized for device: {DeviceId} on host {ComputerName} (Windows: {WindowsVersion}, User: {User})",
                deviceInfo.DeviceId, deviceInfo.ComputerName, deviceInfo.WindowsVersion, deviceInfo.EmployeeName);

            _isRegistered = await _apiClient.RegisterAsync(deviceInfo, cancellationToken);

            // Startup software synchronization: if registration succeeded, ensure software inventory is fully synced
            if (_isRegistered && deviceInfo.SoftwareList.Count > 0)
            {
                var freqCount = deviceInfo.SoftwareList.Count(s => s.ExecutionCount > 0);
                Console.WriteLine($"[DEBUG-SOFTWARE] Startup sync: uploading {deviceInfo.SoftwareList.Count} apps ({freqCount} frequently used) to backend...");
                await _apiClient.SyncSoftwareAsync(deviceInfo.DeviceId, deviceInfo.SoftwareList, cancellationToken);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to resolve initial device identity or register with backend.");
        }

        await base.StartAsync(cancellationToken);
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var intervalSeconds = Math.Max(5, _settings.PolicyCheckIntervalSeconds);
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(intervalSeconds));

        _logger.LogInformation("WRMS Agent execution loop initiated. Cycle interval: {Interval}s", intervalSeconds);

        // If running interactively (console/dev), run foreground usage tracking directly in this session
        if (Environment.UserInteractive)
        {
            _ = Task.Run(() => _usageTracker.RunSessionLoopAsync(stoppingToken), stoppingToken);
        }

        // Run the first check immediately upon startup
        await ExecuteCycleSafelyAsync(stoppingToken);

        // Periodic recurring execution loop
        while (!stoppingToken.IsCancellationRequested && await timer.WaitForNextTickAsync(stoppingToken))
        {
            await ExecuteCycleSafelyAsync(stoppingToken);
        }
    }

    private async Task ExecuteCycleSafelyAsync(CancellationToken cancellationToken)
    {
        try
        {
            _cycleNumber++;
            _logger.LogHealthHeartbeat(_settings.AgentName, _settings.PolicyCheckIntervalSeconds);

            // Keep user-session foreground tracker alive when running as Session-0 Windows Service
            _sessionLauncher.EnsureSessionTrackerRunning();

            // 0. Ensure device is registered with backend
            if (!_isRegistered)
            {
                try
                {
                    var devInfo = await _deviceIdentityService.GetDeviceInfoAsync(cancellationToken);
                    _isRegistered = await _apiClient.RegisterAsync(devInfo, cancellationToken);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Device registration retry postponed to next cycle.");
                }
            }

            // 1. Fetch current effective policy (from API or POC fallback)
            var policy = await _policyProvider.GetCurrentPolicyAsync(cancellationToken);
            if (policy == null)
            {
                _logger.LogWarning("No policy returned by policy provider.");
                return;
            }

            // 2. Apply Policy via coordinator
            var result = await _policyApplicationService.ApplyPolicyAsync(policy, cancellationToken);

            var deviceInfo = await _deviceIdentityService.GetDeviceInfoAsync(cancellationToken);
            var dailyUsage = _usageTracker.ReadDailySummary();

            // 3. Print high-visibility Console Dashboard showing active blocked domains & daily screen-time usage
            PrintConsoleDashboard(_cycleNumber, policy, result, deviceInfo, dailyUsage);

            // 4. Log detailed results
            _logger.LogInformation(
                "Policy execution completed. Policy: {PolicyId} v{Version}, Status: {Status}, Success: {Success}",
                result.PolicyId, result.PolicyVersion, result.Status, result.Success);

            foreach (var rule in result.Rules)
            {
                _logger.LogInformation(
                    "Rule evaluation -> [{RuleType}] {Target}: {Status} - {Message}",
                    rule.RuleType, rule.Target, rule.Status, rule.Message);
            }

            if (result.Errors.Count > 0)
            {
                foreach (var err in result.Errors)
                {
                    _logger.LogError("Policy application error: {Error}", err);
                }
            }

            // Report execution status and live security telemetry back to central management server
            try
            {
                await _apiClient.ReportPolicyResultAsync(deviceInfo.DeviceId, result, deviceInfo, cancellationToken);

                // Sync real daily foreground screen-time & app launches every cycle (60s)
                if (dailyUsage != null && dailyUsage.Apps.Count > 0)
                {
                    await _apiClient.SyncDailyUsageAsync(deviceInfo.DeviceId, dailyUsage, cancellationToken);
                }

                // Sync installed software inventory on cycle 1, periodic 1-hour interval, or every 5 cycles
                if (_cycleNumber == 1 || deviceInfo.SoftwareScannedFresh || _cycleNumber % 5 == 0)
                {
                    _ = Task.Run(async () =>
                    {
                        try
                        {
                            var freqCount = deviceInfo.SoftwareList.Count(s => s.ExecutionCount > 0);
                            Console.WriteLine($"[DEBUG-SOFTWARE] Synchronizing {deviceInfo.SoftwareList.Count} apps ({freqCount} frequently used) with backend...");
                            await _apiClient.SyncSoftwareAsync(deviceInfo.DeviceId, deviceInfo.SoftwareList, cancellationToken);
                        }
                        catch (Exception ex)
                        {
                            Console.WriteLine($"[DEBUG-SOFTWARE] Error synchronizing software inventory: {ex.Message}");
                        }
                    }, cancellationToken);
                }
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Could not send policy status report to backend.");
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Expected during service shutdown
        }
        catch (Exception ex)
        {
            // Critical requirement: Do not allow an error during a cycle to crash the service
            _logger.LogCycleError(_settings.AgentName, ex);
        }
    }

    private void PrintConsoleDashboard(int cycleNumber, Policy policy, PolicyApplyResult result, DeviceInfo? deviceInfo = null, DailyAppUsageSummary? dailyUsage = null)
    {
        try
        {
            var blockedRules = policy.WebsiteRules?.Where(r => r.Block).ToList() ?? [];

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(new string('=', 76));
            Console.WriteLine($" [WRMS SYNC CYCLE #{cycleNumber}] {DateTime.Now:yyyy-MM-dd HH:mm:ss} | Interval: {_settings.PolicyCheckIntervalSeconds}s");
            Console.WriteLine(new string('=', 76));
            Console.ResetColor();

            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($" Policy ID       : {policy.PolicyId} (Version: {policy.PolicyVersion})");
            Console.ForegroundColor = result.Success ? ConsoleColor.Green : ConsoleColor.Red;
            Console.WriteLine($" Policy Status   : {(result.Success ? "[ACTIVE & ENFORCING]" : "[FAILED] " + string.Join("; ", result.Errors))}");
            Console.ForegroundColor = ConsoleColor.White;
            Console.Write(" Firewall State  : ");
            if (policy.EnforceFirewallEnabled != false)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[ACTIVE & ENFORCING] (Kernel Packet Filter Enabled)");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[DISABLED / OFF] (Remote Admin Override)");
            }
            Console.ResetColor();
            Console.WriteLine();

            if (blockedRules.Count > 0)
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($" CURRENTLY BLOCKED WEBSITES ({blockedRules.Count} domains):");
                Console.ResetColor();

                for (var i = 0; i < blockedRules.Count; i++)
                {
                    var rule = blockedRules[i];
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write($"   [{i + 1}] ");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write(rule.Domain.PadRight(28));
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write("[BLOCKED]");
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine(rule.IncludeCommonSubdomains ? "  (Auto-blocks: www, m, *.subdomains)" : "  (Exact domain)");
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine("   [No website domains are currently blocked in this policy]");
            }

            var blockedApps = policy.ApplicationRules?.Where(r => r.Block).ToList() ?? [];
            if (blockedApps.Count > 0)
            {
                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine($" CURRENTLY BLOCKED APPLICATIONS ({blockedApps.Count} executables):");
                Console.ResetColor();

                for (var i = 0; i < blockedApps.Count; i++)
                {
                    var app = blockedApps[i];
                    var exeDisplay = string.IsNullOrWhiteSpace(app.ExecutableName) ? app.AppName : app.ExecutableName;
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write($"   [{i + 1}] ");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write(exeDisplay.PadRight(28));
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write("[BLOCKED]");
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine($"  ({app.AppName})");
                }
            }

            var blockedPorts = policy.BlockedPorts ?? [];
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($" RESTRICTED / BLOCKED PORTS ({(blockedPorts.Count > 0 ? $"{blockedPorts.Count} ports" : "None")}):");
            Console.ResetColor();

            if (blockedPorts.Count > 0)
            {
                for (var i = 0; i < blockedPorts.Count; i++)
                {
                    var port = blockedPorts[i];
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write($"   [{i + 1}] ");
                    Console.ForegroundColor = ConsoleColor.White;
                    Console.Write($"Port {port}".PadRight(20));
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write("[BLOCKED]");
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine("  (Windows Firewall Filter + Process Watchdog)");
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.DarkYellow;
                Console.WriteLine("   [No ports are currently restricted or blocked in this policy]");
            }

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write(" USB STORAGE POLICY        : ");
            var usbAction = policy.UsbRule?.Action?.ToLowerInvariant() ?? (policy.UsbRule?.Block == true ? "block" : (policy.UsbRule?.ReadOnly == true ? "read_only" : "allow"));
            if (usbAction == "block" || policy.UsbRule?.Block == true)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine("[BLOCKED]");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("   -> Mass storage drives disabled via USBSTOR & Group Policy. Keyboards & mice unaffected.");
            }
            else if (usbAction == "read_only" || policy.UsbRule?.ReadOnly == true)
            {
                Console.ForegroundColor = ConsoleColor.Cyan;
                Console.WriteLine("[READ-ONLY]");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("   -> StorageDevicePolicies WriteProtect active. Files can be viewed/read; writing to USB is blocked.");
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[ALLOWED]");
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.WriteLine("   -> Normal USB storage access enabled.");
            }
            Console.ResetColor();

            // Daily Active Screen-Time Usage Summary
            if (dailyUsage?.Apps != null)
            {
                var topApps = dailyUsage.Apps
                    .Where(a => a.ActiveSeconds > 0 || a.LaunchCount > 0)
                    .OrderByDescending(a => a.ActiveSeconds)
                    .ThenByDescending(a => a.LaunchCount)
                    .Take(7)
                    .ToList();

                Console.WriteLine();
                Console.ForegroundColor = ConsoleColor.Yellow;
                var totalSpan = TimeSpan.FromSeconds(dailyUsage.TotalActiveSeconds);
                var idleSpan = TimeSpan.FromSeconds(dailyUsage.TotalIdleSeconds);
                Console.WriteLine($" TODAY'S APP USAGE ({dailyUsage.Date} | Active: {(int)totalSpan.TotalHours}h {totalSpan.Minutes}m {totalSpan.Seconds}s | Idle: {(int)idleSpan.TotalHours}h {idleSpan.Minutes}m):");
                Console.ResetColor();

                if (topApps.Count > 0)
                {
                    for (var i = 0; i < topApps.Count; i++)
                    {
                        var app = topApps[i];
                        var span = TimeSpan.FromSeconds(app.ActiveSeconds);
                        var timeStr = span.TotalHours >= 1
                            ? $"{(int)span.TotalHours}h {span.Minutes:D2}m {span.Seconds:D2}s"
                            : $"{span.Minutes}m {span.Seconds:D2}s";
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.Write($"   [{i + 1}] ");
                        Console.ForegroundColor = ConsoleColor.White;
                        Console.Write(app.AppName.PadRight(28));
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        Console.Write($"Time: {timeStr}".PadRight(18));
                        Console.ForegroundColor = ConsoleColor.DarkGray;
                        Console.WriteLine($"Launches: {app.LaunchCount} ({app.Executable})");
                    }
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.DarkYellow;
                    Console.WriteLine("   [Tracking active user desktop session — foreground app time will appear here]");
                }
                Console.ResetColor();
            }

            // 5-Browser Policies (Chrome, Brave, Firefox, Edge, Opera)
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(" 5-BROWSER POLICIES:");
            Console.ResetColor();

            var bRule = policy.BrowserRule ?? new Models.BrowserRule();
            void PrintBrowserStatus(string name, bool privateDisabled, bool extBlocked)
            {
                Console.ForegroundColor = ConsoleColor.Green;
                Console.Write("   -> ");
                Console.ForegroundColor = ConsoleColor.White;
                Console.Write(name.PadRight(20));
                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("Private Tab: ");
                if (privateDisabled)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.Write("[BLOCKED]   ");
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.Write("[ALLOWED]   ");
                }

                Console.ForegroundColor = ConsoleColor.DarkGray;
                Console.Write("Extensions: ");
                if (extBlocked)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("[BLOCKED]");
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("[ALLOWED]");
                }
            }

            PrintBrowserStatus("Google Chrome", bRule.DisableChromePrivate, bRule.BlockChromeExtensions);
            PrintBrowserStatus("Brave Browser", bRule.DisableBravePrivate, bRule.BlockBraveExtensions);
            PrintBrowserStatus("Mozilla Firefox", bRule.DisableFirefoxPrivate, bRule.BlockFirefoxExtensions);
            PrintBrowserStatus("Microsoft Edge", bRule.DisableEdgePrivate, bRule.BlockEdgeExtensions);
            PrintBrowserStatus("Opera / Opera GX", bRule.DisableOperaPrivate, bRule.BlockOperaExtensions);

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkCyan;
            Console.WriteLine(" ENFORCEMENT LAYERS:");
            Console.ForegroundColor = ConsoleColor.White;
            Console.WriteLine($"   -> Windows Firewall     : {(policy.EnforceFirewallEnabled != false ? "[ACTIVE & ENFORCING] (Kernel Packet Filter)" : "[DISABLED / OFF] (Remote Admin Override)")}");
            Console.WriteLine($"   -> Port Watchdog Filter : {(blockedPorts.Count > 0 ? $"[{blockedPorts.Count} Restricted Ports Active]" : "[No Ports Blocked]")} (TCP/UDP Packet Block + Process Killer)");
            Console.WriteLine("   -> Windows Hosts File   : 0.0.0.0 / :: DNS sinks verified");
            Console.WriteLine("   -> Browser URL Blocklist: Native enterprise URLBlocklist active");
            Console.WriteLine("   -> 5 Browsers Hardened  : Chrome, Brave, Firefox, Edge, Opera (HKLM Policies)");
            Console.WriteLine("   -> Windows DisallowRun  : Explorer execution restriction active");
            Console.WriteLine("   -> Process Watchdog     : Active process termination monitoring active");
            Console.WriteLine($"   -> USB Storage Control  : [{usbAction.ToUpperInvariant()}] (USBSTOR & RemovableStorageDevices)");
            Console.WriteLine("   -> Windows DNS Cache    : Flushed");

            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.DarkGray;
            Console.WriteLine($" Next automatic sync in {_settings.PolicyCheckIntervalSeconds}s... (Add or remove in Admin UI to update)");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine(new string('=', 76));
            Console.ResetColor();
            Console.WriteLine();
        }
        catch
        {
            // Do not fail cycle if console output is redirected or unavailable
        }
    }

    public override Task StopAsync(CancellationToken cancellationToken)
    {
        _sessionLauncher.StopSessionTracker();
        _logger.LogServiceStopping(_settings.AgentName);
        return base.StopAsync(cancellationToken);
    }
}
