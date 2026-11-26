namespace WRMS.Agent.Configuration;

using WRMS.Agent.Constants;

/// <summary>
/// Fine-grained configuration settings for policy enforcement mechanics.
/// Allows customizing hosts path and state storage for testing or custom environments.
/// </summary>
public sealed class PolicySettings
{
    public const string SectionName = "Policy";

    /// <summary>
    /// Path to the system hosts file. Defaults to standard Windows path.
    /// </summary>
    public string HostsFilePath { get; set; } = PolicyConstants.Hosts.DefaultHostsFilePath;

    /// <summary>
    /// Path to the local policy state cache file.
    /// </summary>
    public string StateFilePath { get; set; } = string.Empty;

    /// <summary>
    /// Fallback loopback address for domain redirection.
    /// </summary>
    public string BlockAddress { get; set; } = PolicyConstants.Hosts.BlockAddress;
}

