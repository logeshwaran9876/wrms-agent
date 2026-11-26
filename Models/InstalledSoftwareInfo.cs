namespace WRMS.Agent.Models;

public sealed class InstalledSoftwareInfo
{
    public string Name { get; set; } = string.Empty;
    public string Executable { get; set; } = string.Empty;
    public string Publisher { get; set; } = "Unknown";
    public string Version { get; set; } = "1.0.0";
    public string InstallDate { get; set; } = string.Empty;
    public int ExecutionCount { get; set; }
}
