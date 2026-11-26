namespace WRMS.Agent.Services;

using WRMS.Agent.Models;

/// <summary>
/// Central coordinator orchestrating policy validation, state checking, temporary permissions,
/// and dispatching enforcement to WebsitePolicyService and BrowserPolicyService.
/// </summary>
public interface IPolicyApplicationService
{
    Task<PolicyApplyResult> ApplyPolicyAsync(Policy policy, CancellationToken cancellationToken);

    Task<PolicyApplyResult> RemovePolicyAsync(CancellationToken cancellationToken);
}

