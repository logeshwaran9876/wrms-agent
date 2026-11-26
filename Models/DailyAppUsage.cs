namespace WRMS.Agent.Models;

using System.Text.Json.Serialization;

/// <summary>
/// Represents accurate daily usage metrics for a single desktop application on a calendar day.
/// </summary>
public sealed class DailyAppUsageEntry
{
    [JsonPropertyName("executable")]
    public string Executable { get; set; } = string.Empty;

    [JsonPropertyName("appName")]
    public string AppName { get; set; } = string.Empty;

    [JsonPropertyName("publisher")]
    public string Publisher { get; set; } = "Unknown";

    [JsonPropertyName("activeSeconds")]
    public long ActiveSeconds { get; set; }

    [JsonPropertyName("launchCount")]
    public int LaunchCount { get; set; }

    [JsonPropertyName("firstUsedAt")]
    public string FirstUsedAt { get; set; } = string.Empty;

    [JsonPropertyName("lastUsedAt")]
    public string LastUsedAt { get; set; } = string.Empty;
}

/// <summary>
/// Daily aggregated screen-time and application usage summary for a single workstation and date.
/// </summary>
public sealed class DailyAppUsageSummary
{
    [JsonPropertyName("date")]
    public string Date { get; set; } = DateTime.Now.ToString("yyyy-MM-dd");

    [JsonPropertyName("totalActiveSeconds")]
    public long TotalActiveSeconds { get; set; }

    [JsonPropertyName("totalIdleSeconds")]
    public long TotalIdleSeconds { get; set; }

    [JsonPropertyName("lastUpdatedAt")]
    public string LastUpdatedAt { get; set; } = DateTime.UtcNow.ToString("o");

    [JsonPropertyName("apps")]
    public List<DailyAppUsageEntry> Apps { get; set; } = [];
}
