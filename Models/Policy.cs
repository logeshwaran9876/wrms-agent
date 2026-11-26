namespace WRMS.Agent.Models;

/// <summary>
/// Root enterprise policy definition model containing versioning and rule specifications.
/// </summary>
public sealed class Policy
{
    public string PolicyId { get; set; } = string.Empty;

    public int PolicyVersion { get; set; } = 1;

    public string Description { get; set; } = string.Empty;

    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

    public List<WebsiteRule> WebsiteRules { get; set; } = [];

    public List<ApplicationRule> ApplicationRules { get; set; } = [];

    public BrowserRule BrowserRule { get; set; } = new();

    public UsbRule UsbRule { get; set; } = new();

    public List<int> BlockedPorts { get; set; } = [];
    public bool? EnforceFirewallEnabled { get; set; } = true;
}
