namespace WRMS.Agent.Services;

using Microsoft.Extensions.Logging;
using WRMS.Agent.Constants;
using WRMS.Agent.Models;
using WRMS.Agent.Security;

/// <summary>
/// Main policy execution engine.
/// Coordinates validation, idempotency state evaluation, temporary permission filtering,
/// and delegates enforcement to WebsitePolicyService, BrowserPolicyService, and ApplicationPolicyService.
/// </summary>
public sealed class PolicyApplicationService : IPolicyApplicationService
{
    private readonly ILogger<PolicyApplicationService> _logger;
    private readonly IPolicyValidationService _validationService;
    private readonly IWebsitePolicyService _websitePolicyService;
    private readonly IBrowserPolicyService _browserPolicyService;
    private readonly IApplicationPolicyService _applicationPolicyService;
    private readonly IUsbPolicyService _usbPolicyService;
    private readonly IPolicyStateService _stateService;

    public PolicyApplicationService(
        ILogger<PolicyApplicationService> logger,
        IPolicyValidationService validationService,
        IWebsitePolicyService websitePolicyService,
        IBrowserPolicyService browserPolicyService,
        IApplicationPolicyService applicationPolicyService,
        IUsbPolicyService usbPolicyService,
        IPolicyStateService stateService)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _validationService = validationService ?? throw new ArgumentNullException(nameof(validationService));
        _websitePolicyService = websitePolicyService ?? throw new ArgumentNullException(nameof(websitePolicyService));
        _browserPolicyService = browserPolicyService ?? throw new ArgumentNullException(nameof(browserPolicyService));
        _applicationPolicyService = applicationPolicyService ?? throw new ArgumentNullException(nameof(applicationPolicyService));
        _usbPolicyService = usbPolicyService ?? throw new ArgumentNullException(nameof(usbPolicyService));
        _stateService = stateService ?? throw new ArgumentNullException(nameof(stateService));
    }

    public async Task<PolicyApplyResult> ApplyPolicyAsync(Policy policy, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        // 1. Policy Validation
        var (isValid, validationErrors) = _validationService.ValidatePolicy(policy);
        if (!isValid)
        {
            var errMessage = $"Policy validation rejected: {string.Join("; ", validationErrors)}";
            _logger.LogError(errMessage);
            return PolicyApplyResult.Failure(policy?.PolicyId ?? "UNKNOWN", policy?.PolicyVersion ?? 0, errMessage);
        }

        // 2. Rules Preparation
        var effectiveWebsiteRules = policy.WebsiteRules ?? [];
        var effectiveAppRules = policy.ApplicationRules ?? [];

        // 4. Idempotency Check
        var currentState = await _stateService.GetCurrentStateAsync(cancellationToken);
        if (_stateService.IsPolicyAlreadyApplied(policy, currentState))
        {
            _logger.LogInformation("Policy '{PolicyId}' v{Version} is already applied. No changes required.", policy.PolicyId, policy.PolicyVersion);
            // Even if policy unchanged, run process termination watchdog for active enforcement
            await _applicationPolicyService.TerminateBlockedProcessesAsync(cancellationToken);
            TerminateProcessesOnBlockedPorts(policy.BlockedPorts ?? []);
            return PolicyApplyResult.NoChange(policy.PolicyId, policy.PolicyVersion);
        }

        _logger.LogInformation("Applying Policy '{PolicyId}' v{Version} ({WebCount} website rules, {AppCount} app rules, Browser: Chrome={Chrome}, Edge={Edge})...",
            policy.PolicyId, policy.PolicyVersion, effectiveWebsiteRules.Count, effectiveAppRules.Count,
            policy.BrowserRule.DisableChromePrivate, policy.BrowserRule.DisableEdgePrivate);

        var combinedRules = new List<PolicyRuleResult>();
        var errors = new List<string>();

        // 5. Apply Website Policy
        var websiteResult = await _websitePolicyService.ApplyAsync(effectiveWebsiteRules, cancellationToken);
        combinedRules.AddRange(websiteResult.Rules);
        errors.AddRange(websiteResult.Errors);

        // 6. Apply Browser Policy
        var browserResult = await _browserPolicyService.ApplyAsync(policy.BrowserRule, cancellationToken);
        combinedRules.AddRange(browserResult.Rules);
        errors.AddRange(browserResult.Errors);

        // 6b. Apply Browser Enterprise URLBlocklist for blocked domains (Native "Blocked by Administrator" UI)
        var blockedDomainList = effectiveWebsiteRules.Where(r => r.Block).Select(r => r.Domain).ToList();
        if (blockedDomainList.Count > 0)
        {
            var urlBlockResult = await _browserPolicyService.ApplyUrlBlocklistAsync(blockedDomainList, cancellationToken);
            combinedRules.AddRange(urlBlockResult.Rules);
            errors.AddRange(urlBlockResult.Errors);
        }
        else
        {
            var urlUnblockResult = await _browserPolicyService.RemoveUrlBlocklistAsync(cancellationToken);
            combinedRules.AddRange(urlUnblockResult.Rules);
            errors.AddRange(urlUnblockResult.Errors);
        }

        // 7. Apply Application Control Policy (Windows DisallowRun + Active Process Terminator)
        var appResult = await _applicationPolicyService.ApplyAsync(effectiveAppRules, cancellationToken);
        combinedRules.AddRange(appResult.Rules);
        errors.AddRange(appResult.Errors);

        // 8. Apply USB Storage Policy (Block / Read-Only / Allow)
        var effectiveUsbRule = policy.UsbRule ?? new UsbRule();
        var usbResult = await _usbPolicyService.ApplyAsync(effectiveUsbRule, cancellationToken);
        combinedRules.AddRange(usbResult.Rules);
        errors.AddRange(usbResult.Errors);

        // 8b. Apply Blocked Ports (Windows Firewall inbound/outbound kernel packet filter + Active Process Termination)
        var blockedPorts = policy.BlockedPorts ?? [];
        ApplyBlockedPorts(blockedPorts);
        TerminateProcessesOnBlockedPorts(blockedPorts);

        // 8c. Apply Windows Defender Firewall enforcement (ON / OFF)
        ApplyFirewallState(policy.EnforceFirewallEnabled);

        // 9. Aggregate Results
        var isSuccess = websiteResult.Success && browserResult.Success && appResult.Success && usbResult.Success;
        var status = isSuccess
            ? PolicyConstants.Statuses.Success
            : ((websiteResult.Success || browserResult.Success || appResult.Success || usbResult.Success) ? PolicyConstants.Statuses.PartialSuccess : PolicyConstants.Statuses.Failed);

        var aggregateResult = new PolicyApplyResult
        {
            Success = isSuccess,
            Status = status,
            PolicyId = policy.PolicyId,
            PolicyVersion = policy.PolicyVersion,
            Rules = combinedRules,
            Errors = errors,
            AppliedAt = DateTimeOffset.UtcNow
        };

        // 10. Persist State
        var newState = new PolicyState
        {
            LastAppliedPolicyId = policy.PolicyId,
            LastAppliedPolicyVersion = policy.PolicyVersion,
            LastAppliedAt = aggregateResult.AppliedAt,
            LastApplyStatus = aggregateResult.Status,
            BlockedDomains = effectiveWebsiteRules.Where(r => r.Block).Select(r => r.Domain).ToList(),
            BlockedApplications = effectiveAppRules.Where(r => r.Block).Select(r => r.ExecutableName).ToList(),
            ChromePrivateDisabled = policy.BrowserRule.DisableChromePrivate,
            ChromeExtensionsBlocked = policy.BrowserRule.BlockChromeExtensions,
            BravePrivateDisabled = policy.BrowserRule.DisableBravePrivate,
            BraveExtensionsBlocked = policy.BrowserRule.BlockBraveExtensions,
            FirefoxPrivateDisabled = policy.BrowserRule.DisableFirefoxPrivate,
            FirefoxExtensionsBlocked = policy.BrowserRule.BlockFirefoxExtensions,
            EdgePrivateDisabled = policy.BrowserRule.DisableEdgePrivate,
            EdgeExtensionsBlocked = policy.BrowserRule.BlockEdgeExtensions,
            OperaPrivateDisabled = policy.BrowserRule.DisableOperaPrivate,
            OperaExtensionsBlocked = policy.BrowserRule.BlockOperaExtensions,
            UsbAction = effectiveUsbRule.Action,
            UsbStorageBlocked = effectiveUsbRule.Block,
            UsbStorageReadOnly = effectiveUsbRule.ReadOnly,
            FirewallEnforced = policy.EnforceFirewallEnabled ?? true,
            BlockedPorts = blockedPorts
        };

        await _stateService.SaveStateAsync(newState, cancellationToken);

        _logger.LogInformation("Policy application finished. Status: {Status}, Success: {Success}, Errors: {ErrorCount}",
            aggregateResult.Status, aggregateResult.Success, aggregateResult.Errors.Count);

        return aggregateResult;
    }

    public async Task<PolicyApplyResult> RemovePolicyAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _logger.LogInformation("Removing all WRMS policies from system...");

        var combinedRules = new List<PolicyRuleResult>();
        var errors = new List<string>();

        var webResult = await _websitePolicyService.RemoveAsync(null, cancellationToken);
        combinedRules.AddRange(webResult.Rules);
        errors.AddRange(webResult.Errors);

        var browserResult = await _browserPolicyService.RemoveAsync(cancellationToken);
        combinedRules.AddRange(browserResult.Rules);
        errors.AddRange(browserResult.Errors);

        var urlBlockResult = await _browserPolicyService.RemoveUrlBlocklistAsync(cancellationToken);
        combinedRules.AddRange(urlBlockResult.Rules);
        errors.AddRange(urlBlockResult.Errors);

        var appResult = await _applicationPolicyService.RemoveAsync(cancellationToken);
        combinedRules.AddRange(appResult.Rules);
        errors.AddRange(appResult.Errors);

        var usbResult = await _usbPolicyService.RemoveAsync(cancellationToken);
        combinedRules.AddRange(usbResult.Rules);
        errors.AddRange(usbResult.Errors);

        var isSuccess = webResult.Success && browserResult.Success && appResult.Success && usbResult.Success;

        // Clear local state
        await _stateService.SaveStateAsync(new PolicyState
        {
            LastAppliedPolicyId = string.Empty,
            LastAppliedPolicyVersion = 0,
            LastAppliedAt = DateTimeOffset.UtcNow,
            LastApplyStatus = "Reverted",
            BlockedDomains = [],
            BlockedApplications = [],
            ChromePrivateDisabled = false,
            ChromeExtensionsBlocked = false,
            BravePrivateDisabled = false,
            BraveExtensionsBlocked = false,
            FirefoxPrivateDisabled = false,
            FirefoxExtensionsBlocked = false,
            EdgePrivateDisabled = false,
            EdgeExtensionsBlocked = false,
            OperaPrivateDisabled = false,
            OperaExtensionsBlocked = false,
            UsbAction = "allow",
            UsbStorageBlocked = false,
            UsbStorageReadOnly = false
        }, cancellationToken);

        _logger.LogInformation("All WRMS policies reverted successfully.");
        RunNetshCommand("advfirewall firewall delete rule name=\"WRMS_PORT_BLOCK\"");

        return new PolicyApplyResult
        {
            Success = isSuccess,
            Status = isSuccess ? PolicyConstants.Statuses.Success : PolicyConstants.Statuses.Failed,
            PolicyId = "REMOVAL",
            PolicyVersion = 0,
            Rules = combinedRules,
            Errors = errors,
            AppliedAt = DateTimeOffset.UtcNow
        };
    }

    private void ApplyBlockedPorts(List<int> blockedPorts)
    {
        try
        {
            // Remove previous WRMS port block rules to ensure exact synchronization
            RunNetshCommand("advfirewall firewall delete rule name=\"WRMS_PORT_BLOCK\"");

            foreach (var port in blockedPorts)
            {
                if (port <= 0 || port > 65535) continue;
                RunNetshCommand($"advfirewall firewall add rule name=\"WRMS_PORT_BLOCK\" dir=in action=block protocol=TCP localport={port} description=\"WRMS Port Restriction\"");
                RunNetshCommand($"advfirewall firewall add rule name=\"WRMS_PORT_BLOCK\" dir=in action=block protocol=UDP localport={port} description=\"WRMS Port Restriction\"");
                RunNetshCommand($"advfirewall firewall add rule name=\"WRMS_PORT_BLOCK\" dir=out action=block protocol=TCP localport={port} description=\"WRMS Port Restriction\"");
                RunNetshCommand($"advfirewall firewall add rule name=\"WRMS_PORT_BLOCK\" dir=out action=block protocol=UDP localport={port} description=\"WRMS Port Restriction\"");
            }
            if (blockedPorts.Count > 0)
            {
                _logger.LogInformation("Enforced Windows Firewall block on {Count} restricted ports: [{Ports}].",
                    blockedPorts.Count, string.Join(", ", blockedPorts));
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to apply blocked port firewall rules.");
        }
    }

    private void ApplyFirewallState(bool? enforceEnabled)
    {
        if (!enforceEnabled.HasValue) return;

        try
        {
            var targetState = enforceEnabled.Value ? "on" : "off";
            RunNetshCommand($"advfirewall set allprofiles state {targetState}");

            // Ensure registry consistency across Domain, Standard (Private), and Public profiles
            try
            {
                int val = enforceEnabled.Value ? 1 : 0;
                string[] profiles = ["DomainProfile", "StandardProfile", "PublicProfile"];
                foreach (var p in profiles)
                {
                    using var key = Microsoft.Win32.Registry.LocalMachine.CreateSubKey(
                        $@"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\{p}", true);
                    key?.SetValue("EnableFirewall", val, Microsoft.Win32.RegistryValueKind.DWord);
                }
            }
            catch { }

            if (enforceEnabled.Value)
            {
                _logger.LogInformation("[FIREWALL ENFORCEMENT] Windows Defender Firewall turned ON across all profiles (Domain, Private, Public).");
            }
            else
            {
                _logger.LogWarning("[FIREWALL ENFORCEMENT] Windows Defender Firewall turned OFF across all profiles by Admin Remote Override.");
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to apply Windows Defender Firewall state.");
        }
    }

    private static void RunNetshCommand(string arguments)
    {
        try
        {
            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "netsh.exe",
                Arguments = arguments,
                UseShellExecute = false,
                CreateNoWindow = true,
                WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden,
            };
            using var proc = System.Diagnostics.Process.Start(psi);
            proc?.WaitForExit(3000);
        }
        catch { }
    }

    private void TerminateProcessesOnBlockedPorts(List<int> blockedPorts)
    {
        if (blockedPorts == null || blockedPorts.Count == 0) return;

        try
        {
            var pidsToKill = new HashSet<int>();
            var portsSet = new HashSet<int>(blockedPorts);

            var psi = new System.Diagnostics.ProcessStartInfo
            {
                FileName = "netstat.exe",
                Arguments = "-ano",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true,
                WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden,
            };

            using var proc = System.Diagnostics.Process.Start(psi);
            if (proc != null)
            {
                string output = proc.StandardOutput.ReadToEnd();
                proc.WaitForExit(3000);

                var lines = output.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines)
                {
                    var trimmed = line.Trim();
                    if (!trimmed.StartsWith("TCP", StringComparison.OrdinalIgnoreCase) &&
                        !trimmed.StartsWith("UDP", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var parts = trimmed.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length < 4) continue;

                    string localAddr = parts[1];
                    int colonIdx = localAddr.LastIndexOf(':');
                    if (colonIdx >= 0 && int.TryParse(localAddr.Substring(colonIdx + 1), out int port))
                    {
                        if (portsSet.Contains(port))
                        {
                            string pidStr = parts[^1];
                            if (int.TryParse(pidStr, out int pid) && pid > 4 && pid != Environment.ProcessId)
                            {
                                pidsToKill.Add(pid);
                            }
                        }
                    }
                }
            }

            foreach (var pid in pidsToKill)
            {
                try
                {
                    using var p = System.Diagnostics.Process.GetProcessById(pid);
                    string procName = p.ProcessName;
                    // Protect essential Windows core system processes
                    if (procName.Equals("svchost", StringComparison.OrdinalIgnoreCase) ||
                        procName.Equals("csrss", StringComparison.OrdinalIgnoreCase) ||
                        procName.Equals("smss", StringComparison.OrdinalIgnoreCase) ||
                        procName.Equals("lsass", StringComparison.OrdinalIgnoreCase) ||
                        procName.Equals("services", StringComparison.OrdinalIgnoreCase) ||
                        procName.Equals("wininit", StringComparison.OrdinalIgnoreCase) ||
                        procName.Equals("explorer", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    p.Kill(entireProcessTree: true);
                    _logger.LogWarning(
                        "[PORT WATCHDOG] Process '{ProcessName}' (PID: {Pid}) listening on blocked port was terminated.",
                        procName, pid);
                }
                catch (Exception ex)
                {
                    _logger.LogDebug(ex, "Could not terminate process PID {Pid}.", pid);
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to terminate processes listening on blocked ports.");
        }
    }
}
