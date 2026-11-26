namespace WRMS.Agent.Configuration;

/// <summary>
/// Strongly-typed configuration settings for the WRMS Agent.
/// Mapped from the "Agent" configuration section in appsettings.json.
/// </summary>
public sealed class AgentSettings
{
    public const string SectionName = "Agent";

    /// <summary>
    /// The unique system name for this agent service.
    /// </summary>
    public string AgentName { get; set; } = "WRMS-Agent";

    /// <summary>
    /// The running version of the agent software.
    /// </summary>
    public string AgentVersion { get; set; } = "1.0.0";

    /// <summary>
    /// The assigned corporate employee name for this workstation.
    /// </summary>
    public string EmployeeName { get; set; } = string.Empty;

    /// <summary>
    /// The interval in seconds between consecutive policy evaluation and enforcement cycles.
    /// Default is 60 seconds (minimum allowed is 5 seconds).
    /// </summary>
    public int PolicyCheckIntervalSeconds { get; set; } = 60;

    /// <summary>
    /// Interval in hours between consecutive full port and software inventory telemetry scans.
    /// Default is 1 hour (scans once on install/startup, then once every 1 hour).
    /// </summary>
    public int TelemetryScanIntervalHours { get; set; } = 1;

    /// <summary>
    /// Toggles website blocking policies during the POC phase.
    /// </summary>
    public bool EnablePocWebsiteBlocking { get; set; } = true;

    /// <summary>
    /// Toggles browser restriction policies (e.g., Chrome Incognito) during the POC phase.
    /// </summary>
    public bool EnablePocBrowserPolicy { get; set; } = true;
}

