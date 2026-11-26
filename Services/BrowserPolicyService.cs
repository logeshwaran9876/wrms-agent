namespace WRMS.Agent.Services;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Win32;
using WRMS.Agent.Configuration;
using WRMS.Agent.Constants;
using WRMS.Agent.Models;
using WRMS.Agent.Security;
using WRMS.Agent.Windows;

/// <summary>
/// Enforces official Windows enterprise policies across 5 major browsers:
/// Google Chrome, Brave Browser, Mozilla Firefox, Microsoft Edge, and Opera / Opera GX.
/// Blocks private / incognito browsing and enforces extension installation lockdown.
/// </summary>
public sealed class BrowserPolicyService : IBrowserPolicyService
{
    private readonly ILogger<BrowserPolicyService> _logger;
    private readonly IWindowsRegistryService _registryService;
    private readonly IPrivilegeService _privilegeService;
    private readonly AgentSettings _agentSettings;

    public BrowserPolicyService(
        ILogger<BrowserPolicyService> logger,
        IWindowsRegistryService registryService,
        IPrivilegeService privilegeService,
        IOptions<AgentSettings> agentSettings)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _registryService = registryService ?? throw new ArgumentNullException(nameof(registryService));
        _privilegeService = privilegeService ?? throw new ArgumentNullException(nameof(privilegeService));
        _agentSettings = agentSettings?.Value ?? new AgentSettings();
    }

    public async Task<PolicyApplyResult> ApplyAsync(BrowserRule rule, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!_agentSettings.EnablePocBrowserPolicy)
        {
            _logger.LogInformation("Browser policy enforcement is disabled via AgentSettings.");
            return PolicyApplyResult.Successful("BROWSER-POLICY", 1, [
                PolicyRuleResult.Skipped("Browser", "All", "Browser policy disabled in configuration.")
            ]);
        }

        if (!_privilegeService.IsRunningAsAdministrator())
        {
            var msg = "Insufficient privileges: Applying browser policies requires administrator elevation.";
            _logger.LogError(msg);
            return PolicyApplyResult.Failure("BROWSER-POLICY", 1, msg);
        }

        var results = new List<PolicyRuleResult>();

        // ==========================================
        // 1. Google Chrome (Incognito & Extensions)
        // ==========================================
        try
        {
            if (rule.DisableChromePrivate)
            {
                _logger.LogInformation("Chrome: Disabling Incognito mode...");
                await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.ChromePoliciesSubKey, PolicyConstants.Registry.ChromeIncognitoValueName, PolicyConstants.Registry.IncognitoModeDisabled, cancellationToken);
                await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.ChromePoliciesSubKey, PolicyConstants.Registry.WrmsOwnershipTagValueName, PolicyConstants.Registry.WrmsOwnershipValue, cancellationToken);
                results.Add(PolicyRuleResult.Succeeded("Browser", "Chrome Incognito", "Google Chrome Incognito mode disabled."));
            }
            else
            {
                await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.ChromePoliciesSubKey, PolicyConstants.Registry.ChromeIncognitoValueName, cancellationToken);
                results.Add(PolicyRuleResult.Succeeded("Browser", "Chrome Incognito", "Google Chrome Incognito mode allowed."));
            }

            if (rule.BlockChromeExtensions)
            {
                await _registryService.SetStringValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.ChromeExtensionBlocklistSubKey, "1", "*", cancellationToken);
                results.Add(PolicyRuleResult.Succeeded("Browser", "Chrome Extensions", "All unauthorized Chrome extensions blocked (*)."));
            }
            else
            {
                await _registryService.DeleteSubKeyTreeAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.ChromeExtensionBlocklistSubKey, cancellationToken);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed applying Chrome policies.");
            results.Add(PolicyRuleResult.Failed("Browser", "Google Chrome", ex.Message));
        }

        // ==========================================
        // 2. Brave Browser (Private Window, Tor, Extensions)
        // ==========================================
        try
        {
            if (rule.DisableBravePrivate)
            {
                _logger.LogInformation("Brave: Disabling Private & Tor windows...");
                await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.BravePoliciesSubKey, PolicyConstants.Registry.ChromeIncognitoValueName, PolicyConstants.Registry.IncognitoModeDisabled, cancellationToken);
                await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.BravePoliciesSubKey, PolicyConstants.Registry.BraveTorValueName, 1, cancellationToken);
                await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.BravePoliciesSubKey, PolicyConstants.Registry.WrmsOwnershipTagValueName, PolicyConstants.Registry.WrmsOwnershipValue, cancellationToken);
                results.Add(PolicyRuleResult.Succeeded("Browser", "Brave Private Browsing", "Brave Private & Tor windows disabled."));
            }
            else
            {
                await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.BravePoliciesSubKey, PolicyConstants.Registry.ChromeIncognitoValueName, cancellationToken);
                await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.BravePoliciesSubKey, PolicyConstants.Registry.BraveTorValueName, cancellationToken);
                results.Add(PolicyRuleResult.Succeeded("Browser", "Brave Private Browsing", "Brave Private & Tor windows allowed."));
            }

            if (rule.BlockBraveExtensions)
            {
                await _registryService.SetStringValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.BraveExtensionBlocklistSubKey, "1", "*", cancellationToken);
                results.Add(PolicyRuleResult.Succeeded("Browser", "Brave Extensions", "Brave extensions installation blocked (*)."));
            }
            else
            {
                await _registryService.DeleteSubKeyTreeAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.BraveExtensionBlocklistSubKey, cancellationToken);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed applying Brave policies.");
            results.Add(PolicyRuleResult.Failed("Browser", "Brave Browser", ex.Message));
        }

        // ==========================================
        // 3. Mozilla Firefox (Private Browsing & Add-ons)
        // ==========================================
        try
        {
            if (rule.DisableFirefoxPrivate)
            {
                _logger.LogInformation("Firefox: Disabling Private Browsing...");
                await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.FirefoxPoliciesSubKey, PolicyConstants.Registry.FirefoxPrivateValueName, 1, cancellationToken);
                await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.FirefoxPoliciesSubKey, PolicyConstants.Registry.WrmsOwnershipTagValueName, PolicyConstants.Registry.WrmsOwnershipValue, cancellationToken);
                results.Add(PolicyRuleResult.Succeeded("Browser", "Firefox Private Browsing", "Mozilla Firefox Private Browsing mode disabled."));
            }
            else
            {
                await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.FirefoxPoliciesSubKey, PolicyConstants.Registry.FirefoxPrivateValueName, cancellationToken);
                results.Add(PolicyRuleResult.Succeeded("Browser", "Firefox Private Browsing", "Mozilla Firefox Private Browsing mode allowed."));
            }

            if (rule.BlockFirefoxExtensions)
            {
                await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.FirefoxPoliciesSubKey, PolicyConstants.Registry.FirefoxBlockAddonsValueName, 1, cancellationToken);
                results.Add(PolicyRuleResult.Succeeded("Browser", "Firefox Extensions", "Mozilla Firefox Add-ons installation blocked."));
            }
            else
            {
                await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.FirefoxPoliciesSubKey, PolicyConstants.Registry.FirefoxBlockAddonsValueName, cancellationToken);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed applying Firefox policies.");
            results.Add(PolicyRuleResult.Failed("Browser", "Mozilla Firefox", ex.Message));
        }

        // ==========================================
        // 4. Microsoft Edge (InPrivate & Extensions)
        // ==========================================
        try
        {
            if (rule.DisableEdgePrivate)
            {
                _logger.LogInformation("Edge: Disabling InPrivate mode...");
                await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.EdgePoliciesSubKey, PolicyConstants.Registry.EdgeInPrivateValueName, PolicyConstants.Registry.IncognitoModeDisabled, cancellationToken);
                await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.EdgePoliciesSubKey, PolicyConstants.Registry.WrmsOwnershipTagValueName, PolicyConstants.Registry.WrmsOwnershipValue, cancellationToken);
                results.Add(PolicyRuleResult.Succeeded("Browser", "Edge InPrivate", "Microsoft Edge InPrivate mode disabled."));
            }
            else
            {
                await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.EdgePoliciesSubKey, PolicyConstants.Registry.EdgeInPrivateValueName, cancellationToken);
                results.Add(PolicyRuleResult.Succeeded("Browser", "Edge InPrivate", "Microsoft Edge InPrivate mode allowed."));
            }

            if (rule.BlockEdgeExtensions)
            {
                await _registryService.SetStringValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.EdgeExtensionBlocklistSubKey, "1", "*", cancellationToken);
                results.Add(PolicyRuleResult.Succeeded("Browser", "Edge Extensions", "Microsoft Edge extensions installation blocked (*)."));
            }
            else
            {
                await _registryService.DeleteSubKeyTreeAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.EdgeExtensionBlocklistSubKey, cancellationToken);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed applying Edge policies.");
            results.Add(PolicyRuleResult.Failed("Browser", "Microsoft Edge", ex.Message));
        }

        // ==========================================
        // 5. Opera & Opera GX (Private Window & Extensions)
        // ==========================================
        try
        {
            if (rule.DisableOperaPrivate)
            {
                _logger.LogInformation("Opera: Disabling Private Browsing window...");
                await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.OperaPoliciesSubKey, PolicyConstants.Registry.ChromeIncognitoValueName, PolicyConstants.Registry.IncognitoModeDisabled, cancellationToken);
                await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.ChromiumPoliciesSubKey, PolicyConstants.Registry.ChromeIncognitoValueName, PolicyConstants.Registry.IncognitoModeDisabled, cancellationToken);
                await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.OperaPoliciesSubKey, PolicyConstants.Registry.WrmsOwnershipTagValueName, PolicyConstants.Registry.WrmsOwnershipValue, cancellationToken);
                results.Add(PolicyRuleResult.Succeeded("Browser", "Opera Private Browsing", "Opera & Opera GX Private window disabled."));
            }
            else
            {
                await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.OperaPoliciesSubKey, PolicyConstants.Registry.ChromeIncognitoValueName, cancellationToken);
                await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.ChromiumPoliciesSubKey, PolicyConstants.Registry.ChromeIncognitoValueName, cancellationToken);
                results.Add(PolicyRuleResult.Succeeded("Browser", "Opera Private Browsing", "Opera Private window allowed."));
            }

            if (rule.BlockOperaExtensions)
            {
                await _registryService.SetStringValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.OperaExtensionBlocklistSubKey, "1", "*", cancellationToken);
                await _registryService.SetStringValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.ChromiumExtensionBlocklistSubKey, "1", "*", cancellationToken);
                results.Add(PolicyRuleResult.Succeeded("Browser", "Opera Extensions", "Opera extensions blocked (*)."));
            }
            else
            {
                await _registryService.DeleteSubKeyTreeAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.OperaExtensionBlocklistSubKey, cancellationToken);
                await _registryService.DeleteSubKeyTreeAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.ChromiumExtensionBlocklistSubKey, cancellationToken);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed applying Opera policies.");
            results.Add(PolicyRuleResult.Failed("Browser", "Opera", ex.Message));
        }

        // ==========================================
        // 6. Enterprise Hardening (DoH & QUIC bypass prevention)
        // ==========================================
        try
        {
            await _registryService.SetStringValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.ChromePoliciesSubKey, PolicyConstants.Registry.DnsOverHttpsModeValueName, PolicyConstants.Registry.DnsOverHttpsModeOff, cancellationToken);
            await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.ChromePoliciesSubKey, PolicyConstants.Registry.QuicAllowedValueName, PolicyConstants.Registry.QuicDisabledValue, cancellationToken);
            await _registryService.SetStringValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.EdgePoliciesSubKey, PolicyConstants.Registry.DnsOverHttpsModeValueName, PolicyConstants.Registry.DnsOverHttpsModeOff, cancellationToken);
            await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.EdgePoliciesSubKey, PolicyConstants.Registry.QuicAllowedValueName, PolicyConstants.Registry.QuicDisabledValue, cancellationToken);
            results.Add(PolicyRuleResult.Succeeded("Browser", "Secure DNS & QUIC Hardening", "DNS-over-HTTPS & QUIC disabled to enforce domain sink policies."));
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Hardening warning: Secure DNS / QUIC.");
        }

        var anyFailures = results.Any(r => !r.Success);
        return anyFailures
            ? PolicyApplyResult.Partial("BROWSER-POLICY", 1, results, results.Where(r => !r.Success).Select(r => r.Message).ToList())
            : PolicyApplyResult.Successful("BROWSER-POLICY", 1, results);
    }

    public async Task<PolicyApplyResult> ApplyUrlBlocklistAsync(IReadOnlyCollection<string> domains, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!_privilegeService.IsRunningAsAdministrator())
        {
            var msg = "Insufficient privileges: Applying browser URLBlocklist requires administrator elevation.";
            _logger.LogError(msg);
            return PolicyApplyResult.Failure("BROWSER-URLBLOCKLIST", 1, msg);
        }

        var results = new List<PolicyRuleResult>();
        var distinctDomains = domains.Distinct(StringComparer.OrdinalIgnoreCase).ToList();

        try
        {
            _logger.LogInformation("Applying Chromium & Edge URLBlocklist policies for {Count} domains...", distinctDomains.Count);

            await _registryService.DeleteSubKeyTreeAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.ChromeUrlBlocklistSubKey, cancellationToken);
            await _registryService.DeleteSubKeyTreeAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.EdgeUrlBlocklistSubKey, cancellationToken);

            var patternsToBlock = new List<string>();
            foreach (var domain in distinctDomains)
            {
                patternsToBlock.Add(domain);
                patternsToBlock.Add($"*://*.{domain}/*");
                patternsToBlock.Add($"*://{domain}/*");
            }

            var uniquePatterns = patternsToBlock.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
            var index = 1;
            foreach (var pattern in uniquePatterns)
            {
                await _registryService.SetStringValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.ChromeUrlBlocklistSubKey, index.ToString(), pattern, cancellationToken);
                await _registryService.SetStringValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.EdgeUrlBlocklistSubKey, index.ToString(), pattern, cancellationToken);
                index++;
            }

            await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.ChromeUrlBlocklistSubKey, PolicyConstants.Registry.WrmsOwnershipTagValueName, PolicyConstants.Registry.WrmsOwnershipValue, cancellationToken);

            results.Add(PolicyRuleResult.Succeeded("Browser", "Browser URLBlocklist", $"Native enterprise blocklist applied for {uniquePatterns.Count} patterns across {distinctDomains.Count} domains."));
            return PolicyApplyResult.Successful("BROWSER-URLBLOCKLIST", 1, results);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to apply browser URLBlocklist.");
            return PolicyApplyResult.Failure("BROWSER-URLBLOCKLIST", 1, ex.Message);
        }
    }

    public async Task<PolicyApplyResult> RemoveUrlBlocklistAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_privilegeService.IsRunningAsAdministrator()) return PolicyApplyResult.Failure("BROWSER-URLBLOCKLIST", 1, "Elevation required.");

        try
        {
            await _registryService.DeleteSubKeyTreeAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.ChromeUrlBlocklistSubKey, cancellationToken);
            await _registryService.DeleteSubKeyTreeAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.EdgeUrlBlocklistSubKey, cancellationToken);
            return PolicyApplyResult.Successful("BROWSER-URLBLOCKLIST", 1, [
                PolicyRuleResult.Succeeded("Browser", "Browser URLBlocklist", "URLBlocklist policy subkeys removed.")
            ]);
        }
        catch (Exception ex)
        {
            return PolicyApplyResult.Failure("BROWSER-URLBLOCKLIST", 1, ex.Message);
        }
    }

    public async Task<PolicyApplyResult> RemoveAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (!_privilegeService.IsRunningAsAdministrator()) return PolicyApplyResult.Failure("BROWSER-POLICY", 1, "Elevation required.");

        var results = new List<PolicyRuleResult>();

        // Revert 5 browsers
        try
        {
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.ChromePoliciesSubKey, PolicyConstants.Registry.ChromeIncognitoValueName, cancellationToken);
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.ChromePoliciesSubKey, PolicyConstants.Registry.DnsOverHttpsModeValueName, cancellationToken);
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.ChromePoliciesSubKey, PolicyConstants.Registry.QuicAllowedValueName, cancellationToken);
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.ChromePoliciesSubKey, PolicyConstants.Registry.WrmsOwnershipTagValueName, cancellationToken);
            await _registryService.DeleteSubKeyTreeAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.ChromeExtensionBlocklistSubKey, cancellationToken);

            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.BravePoliciesSubKey, PolicyConstants.Registry.ChromeIncognitoValueName, cancellationToken);
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.BravePoliciesSubKey, PolicyConstants.Registry.BraveTorValueName, cancellationToken);
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.BravePoliciesSubKey, PolicyConstants.Registry.WrmsOwnershipTagValueName, cancellationToken);
            await _registryService.DeleteSubKeyTreeAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.BraveExtensionBlocklistSubKey, cancellationToken);

            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.FirefoxPoliciesSubKey, PolicyConstants.Registry.FirefoxPrivateValueName, cancellationToken);
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.FirefoxPoliciesSubKey, PolicyConstants.Registry.FirefoxBlockAddonsValueName, cancellationToken);
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.FirefoxPoliciesSubKey, PolicyConstants.Registry.WrmsOwnershipTagValueName, cancellationToken);

            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.EdgePoliciesSubKey, PolicyConstants.Registry.EdgeInPrivateValueName, cancellationToken);
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.EdgePoliciesSubKey, PolicyConstants.Registry.DnsOverHttpsModeValueName, cancellationToken);
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.EdgePoliciesSubKey, PolicyConstants.Registry.QuicAllowedValueName, cancellationToken);
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.EdgePoliciesSubKey, PolicyConstants.Registry.WrmsOwnershipTagValueName, cancellationToken);
            await _registryService.DeleteSubKeyTreeAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.EdgeExtensionBlocklistSubKey, cancellationToken);

            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.OperaPoliciesSubKey, PolicyConstants.Registry.ChromeIncognitoValueName, cancellationToken);
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.OperaPoliciesSubKey, PolicyConstants.Registry.WrmsOwnershipTagValueName, cancellationToken);
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.ChromiumPoliciesSubKey, PolicyConstants.Registry.ChromeIncognitoValueName, cancellationToken);
            await _registryService.DeleteSubKeyTreeAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.OperaExtensionBlocklistSubKey, cancellationToken);
            await _registryService.DeleteSubKeyTreeAsync(RegistryHive.LocalMachine, PolicyConstants.Registry.ChromiumExtensionBlocklistSubKey, cancellationToken);

            results.Add(PolicyRuleResult.Succeeded("Browser", "Browser Policies Reverted", "All browser private mode and extension restrictions restored to default."));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to revert browser policies.");
        }

        return PolicyApplyResult.Successful("BROWSER-POLICY", 1, results);
    }
}
