namespace WRMS.Agent.Policies;

using WRMS.Agent.Models;

/// <summary>
/// Specific interface for the POC policy supplier.
/// </summary>
public interface IPocPolicyProvider : IPolicyProvider
{
    /// <summary>
    /// Returns the verified test policy for the POC.
    /// </summary>
    Task<Policy> GetPolicyAsync(CancellationToken cancellationToken);
}

