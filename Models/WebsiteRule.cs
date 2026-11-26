namespace WRMS.Agent.Models;

/// <summary>
/// Rule governing access to a specific website domain.
/// </summary>
public sealed class WebsiteRule
{
    /// <summary>
    /// Normalized domain (e.g., "youtube.com").
    /// </summary>
    public string Domain { get; set; } = string.Empty;

    /// <summary>
    /// Whether the domain should be blocked.
    /// </summary>
    public bool Block { get; set; } = true;

    /// <summary>
    /// Whether common subdomains (such as www., m., music.) should be automatically blocked.
    /// </summary>
    public bool IncludeCommonSubdomains { get; set; } = true;
}

