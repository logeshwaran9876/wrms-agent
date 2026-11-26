namespace WRMS.Agent.Windows;

/// <summary>
/// Abstraction for managing domain blocking entries inside the Windows hosts file.
/// </summary>
public interface IHostsFileManager
{
    /// <summary>
    /// Applies block entries for the specified domains, isolated between WRMS marker comments.
    /// </summary>
    Task ApplyBlocksAsync(IReadOnlyCollection<string> domains, CancellationToken cancellationToken);

    /// <summary>
    /// Removes specified blocked domains, or all WRMS-managed blocks if domains is null.
    /// </summary>
    Task RemoveBlocksAsync(IReadOnlyCollection<string>? domains, CancellationToken cancellationToken);

    /// <summary>
    /// Retrieves all domains currently blocked by WRMS within the hosts file.
    /// </summary>
    Task<IReadOnlyCollection<string>> GetCurrentlyBlockedDomainsAsync(CancellationToken cancellationToken);
}

