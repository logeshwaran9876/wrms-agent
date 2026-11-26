namespace WRMS.Agent.Services;

using WRMS.Agent.Models;

/// <summary>
/// Abstraction for applying and removing website restriction policies.
/// Decouples the policy contract from the underlying Windows mechanism (hosts file vs gateway/filter).
/// </summary>
public interface IWebsitePolicyService
{
    Task<PolicyApplyResult> ApplyAsync(
        IReadOnlyCollection<WebsiteRule> rules,
        CancellationToken cancellationToken);

    Task<PolicyApplyResult> RemoveAsync(
        IReadOnlyCollection<WebsiteRule>? rules,
        CancellationToken cancellationToken);
}

