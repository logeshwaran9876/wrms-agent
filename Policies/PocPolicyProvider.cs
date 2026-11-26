namespace WRMS.Agent.Policies;

using Microsoft.Extensions.Logging;
using WRMS.Agent.Models;

/// <summary>
/// Hard-coded POC policy provider.
/// Isolates test rules into a dedicated component so no URLs or registry keys leak into services.
/// Later replaced with ApiPolicyProvider during backend rollout.
/// </summary>
public sealed class PocPolicyProvider : IPocPolicyProvider
{
    private readonly ILogger<PocPolicyProvider> _logger;

    public PocPolicyProvider(ILogger<PocPolicyProvider> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public Task<Policy> GetPolicyAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        _logger.LogInformation("Loading clean fallback policy (0 static rules)...");

        var policy = new Policy
        {
            PolicyId = "DYNAMIC-FALLBACK-001",
            PolicyVersion = 1,
            Description = "WRMS Clean Policy (Fully Dynamic - No Static Rules)",
            CreatedAt = DateTimeOffset.UtcNow,
            WebsiteRules = [],
            BrowserRule = new BrowserRule
            {
                DisableChromePrivate = true,
                DisableBravePrivate = true,
                DisableFirefoxPrivate = true,
                DisableEdgePrivate = true,
                DisableOperaPrivate = true
            }
        };

        _logger.LogInformation("Clean policy '{PolicyId}' loaded. Rules: {WebsitesCount} website rules (Fully Dynamic).",
            policy.PolicyId, policy.WebsiteRules.Count);

        return Task.FromResult(policy);
    }

    public async Task<Policy?> GetCurrentPolicyAsync(CancellationToken cancellationToken)
    {
        return await GetPolicyAsync(cancellationToken);
    }
}

