namespace WRMS.Agent.Services;

using WRMS.Agent.Models;

/// <summary>
/// Abstraction for tracking and persisting local policy application state.
/// Ensures idempotency and prevents redundant mutations to the operating system.
/// </summary>
public interface IPolicyStateService
{
    Task<PolicyState?> GetCurrentStateAsync(CancellationToken cancellationToken);

    Task SaveStateAsync(PolicyState state, CancellationToken cancellationToken);

    /// <summary>
    /// Determines whether the desired policy is already identical to the current applied state.
    /// </summary>
    bool IsPolicyAlreadyApplied(Policy policy, PolicyState? currentState);
}

