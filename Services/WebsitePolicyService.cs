namespace WRMS.Agent.Services;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WRMS.Agent.Configuration;
using WRMS.Agent.Models;
using WRMS.Agent.Security;
using WRMS.Agent.Windows;

/// <summary>
/// Enforces and reverts website restrictions using Windows hosts management.
/// Handles domain normalization, subdomain expansion, privilege checks, and verification.
/// </summary>
public sealed class WebsitePolicyService : IWebsitePolicyService
{
    private readonly ILogger<WebsitePolicyService> _logger;
    private readonly IHostsFileManager _hostsFileManager;
    private readonly IPolicyValidationService _validationService;
    private readonly IPrivilegeService _privilegeService;
    private readonly AgentSettings _agentSettings;

    public WebsitePolicyService(
        ILogger<WebsitePolicyService> logger,
        IHostsFileManager hostsFileManager,
        IPolicyValidationService validationService,
        IPrivilegeService privilegeService,
        IOptions<AgentSettings> agentSettings)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _hostsFileManager = hostsFileManager ?? throw new ArgumentNullException(nameof(hostsFileManager));
        _validationService = validationService ?? throw new ArgumentNullException(nameof(validationService));
        _privilegeService = privilegeService ?? throw new ArgumentNullException(nameof(privilegeService));
        _agentSettings = agentSettings?.Value ?? new AgentSettings();
    }

    public async Task<PolicyApplyResult> ApplyAsync(
        IReadOnlyCollection<WebsiteRule> rules,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!_agentSettings.EnablePocWebsiteBlocking)
        {
            _logger.LogInformation("Website policy enforcement is disabled via AgentSettings:EnablePocWebsiteBlocking.");
            return PolicyApplyResult.Successful("WEBSITE-POLICY", 1, [
                PolicyRuleResult.Skipped("Website", "All", "Website blocking disabled in configuration.")
            ]);
        }

        if (!_privilegeService.IsRunningAsAdministrator())
        {
            var msg = "Insufficient privileges: Applying Windows hosts website policy requires administrator elevation.";
            _logger.LogError(msg);
            return PolicyApplyResult.Failure("WEBSITE-POLICY", 1, msg);
        }

        var ruleResults = new List<PolicyRuleResult>();
        var domainsToBlock = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rule in rules)
        {
            if (!rule.Block)
            {
                ruleResults.Add(PolicyRuleResult.Skipped("Website", rule.Domain, "Rule specifies Block = false."));
                continue;
            }

            var normalized = _validationService.NormalizeDomain(rule.Domain);
            if (!_validationService.IsValidDomain(normalized))
            {
                ruleResults.Add(PolicyRuleResult.Failed("Website", rule.Domain, "Domain failed validation check."));
                continue;
            }

            domainsToBlock.Add(normalized);

            // Subdomain expansion
            if (rule.IncludeCommonSubdomains)
            {
                foreach (var subdomain in ExpandCommonSubdomains(normalized))
                {
                    domainsToBlock.Add(subdomain);
                }
            }

            ruleResults.Add(PolicyRuleResult.Succeeded("Website", normalized, $"Block scheduled for domain and subdomains."));
        }

        try
        {
            _logger.LogInformation("Applying {Count} resolved domains to Windows hosts file...", domainsToBlock.Count);
            await _hostsFileManager.ApplyBlocksAsync(domainsToBlock, cancellationToken);

            // Verification phase
            var currentlyBlocked = await _hostsFileManager.GetCurrentlyBlockedDomainsAsync(cancellationToken);
            var missing = domainsToBlock.Where(d => !currentlyBlocked.Contains(d, StringComparer.OrdinalIgnoreCase)).ToList();

            if (missing.Count > 0)
            {
                var errorMsg = $"Verification warning: {missing.Count} domains were not found in hosts after write: {string.Join(", ", missing)}";
                _logger.LogWarning(errorMsg);
                return PolicyApplyResult.Partial("WEBSITE-POLICY", 1, ruleResults, [errorMsg]);
            }

            _logger.LogInformation("Website policy applied and verified successfully.");
            return PolicyApplyResult.Successful("WEBSITE-POLICY", 1, ruleResults);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to apply website policy.");
            return PolicyApplyResult.Failure("WEBSITE-POLICY", 1, ex.Message, ruleResults);
        }
    }

    public async Task<PolicyApplyResult> RemoveAsync(
        IReadOnlyCollection<WebsiteRule>? rules,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        if (!_privilegeService.IsRunningAsAdministrator())
        {
            var msg = "Insufficient privileges: Removing Windows hosts website policy requires administrator elevation.";
            _logger.LogError(msg);
            return PolicyApplyResult.Failure("WEBSITE-POLICY", 1, msg);
        }

        try
        {
            if (rules == null || rules.Count == 0)
            {
                _logger.LogInformation("Reverting all WRMS website blocks...");
                await _hostsFileManager.RemoveBlocksAsync(null, cancellationToken);
            }
            else
            {
                var domainsToRemove = new List<string>();
                foreach (var rule in rules)
                {
                    var normalized = _validationService.NormalizeDomain(rule.Domain);
                    domainsToRemove.Add(normalized);
                    if (rule.IncludeCommonSubdomains)
                    {
                        domainsToRemove.AddRange(ExpandCommonSubdomains(normalized));
                    }
                }

                _logger.LogInformation("Reverting {Count} specific domains from WRMS blocks...", domainsToRemove.Count);
                await _hostsFileManager.RemoveBlocksAsync(domainsToRemove, cancellationToken);
            }

            return PolicyApplyResult.Successful("WEBSITE-POLICY", 1, [
                PolicyRuleResult.Succeeded("Website", "All", "WRMS website blocks reverted successfully.")
            ]);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to remove website policy.");
            return PolicyApplyResult.Failure("WEBSITE-POLICY", 1, ex.Message);
        }
    }

    private static IEnumerable<string> ExpandCommonSubdomains(string domain)
    {
        // Custom domain subdomains for popular services like YouTube
        if (domain.Equals("youtube.com", StringComparison.OrdinalIgnoreCase))
        {
            yield return "www.youtube.com";
            yield return "m.youtube.com";
            yield return "music.youtube.com";
            yield return "gaming.youtube.com";
        }
        else if (domain.Equals("facebook.com", StringComparison.OrdinalIgnoreCase))
        {
            yield return "www.facebook.com";
            yield return "m.facebook.com";
            yield return "web.facebook.com";
        }
        else if (!domain.StartsWith("www.", StringComparison.OrdinalIgnoreCase))
        {
            yield return $"www.{domain}";
        }
    }
}

