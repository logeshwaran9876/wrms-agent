namespace WRMS.Agent.Services;

using WRMS.Agent.Models;

/// <summary>
/// Abstraction for enforcing and reverting enterprise browser policies on the Windows machine.
/// Supports Chrome Incognito disabling in POC and prepares architecture for Microsoft Edge InPrivate.
/// </summary>
public interface IBrowserPolicyService
{
    Task<PolicyApplyResult> ApplyAsync(BrowserRule rule, CancellationToken cancellationToken);

    Task<PolicyApplyResult> ApplyUrlBlocklistAsync(IReadOnlyCollection<string> domains, CancellationToken cancellationToken);

    Task<PolicyApplyResult> RemoveAsync(CancellationToken cancellationToken);

    Task<PolicyApplyResult> RemoveUrlBlocklistAsync(CancellationToken cancellationToken);
}

