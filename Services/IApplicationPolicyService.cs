namespace WRMS.Agent.Services;

using WRMS.Agent.Models;

/// <summary>
/// Service responsible for enforcing executable application restrictions on Windows endpoints.
/// Uses native Windows Explorer DisallowRun enterprise registry policies paired with
/// active process termination watchdog.
/// </summary>
public interface IApplicationPolicyService
{
    Task<(bool Success, List<PolicyRuleResult> Rules, List<string> Errors)> ApplyAsync(
        IReadOnlyList<ApplicationRule> rules,
        CancellationToken cancellationToken);

    Task<(bool Success, List<PolicyRuleResult> Rules, List<string> Errors)> RemoveAsync(
        CancellationToken cancellationToken);

    Task TerminateBlockedProcessesAsync(CancellationToken cancellationToken);
}
