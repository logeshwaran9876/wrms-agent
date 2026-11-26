namespace WRMS.Agent.Models;

/// <summary>
/// Persisted state tracking the last applied policy configuration on this device.
/// Enables idempotent execution and prevents redundant modifications to the operating system.
/// </summary>
public sealed class PolicyState
{
    public string LastAppliedPolicyId { get; set; } = string.Empty;

    public int LastAppliedPolicyVersion { get; set; }

    public DateTimeOffset LastAppliedAt { get; set; }

    public string LastApplyStatus { get; set; } = string.Empty;

    public List<string> BlockedDomains { get; set; } = [];

    public List<string> BlockedApplications { get; set; } = [];

    public bool ChromePrivateDisabled { get; set; }
    public bool ChromeExtensionsBlocked { get; set; }
    public bool BravePrivateDisabled { get; set; }
    public bool BraveExtensionsBlocked { get; set; }
    public bool FirefoxPrivateDisabled { get; set; }
    public bool FirefoxExtensionsBlocked { get; set; }
    public bool EdgePrivateDisabled { get; set; }
    public bool EdgeExtensionsBlocked { get; set; }
    public bool OperaPrivateDisabled { get; set; }
    public bool OperaExtensionsBlocked { get; set; }

    public string UsbAction { get; set; } = "allow";

    public bool UsbStorageBlocked { get; set; }

    public bool UsbStorageReadOnly { get; set; }

    public bool FirewallEnforced { get; set; } = true;

    public List<int> BlockedPorts { get; set; } = [];
}
