namespace WRMS.Agent.Policies;

using WRMS.Agent.Models;

/// <summary>
/// Common abstraction for obtaining restriction policies.
/// Decouples policy origin (hard-coded POC, local file, or REST API) from the enforcement engine.
/// </summary>
public interface IPolicyProvider
{
    /// <summary>
    /// Retrieves the current effective policy for this device.
    /// </summary>
    Task<Policy?> GetCurrentPolicyAsync(CancellationToken cancellationToken);
}

