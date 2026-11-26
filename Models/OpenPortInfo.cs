namespace WRMS.Agent.Models;

public sealed class OpenPortInfo
{
    public int Port { get; set; }
    public string Protocol { get; set; } = "TCP";
    public string ProcessName { get; set; } = string.Empty;
    public bool IsAllowed { get; set; } = true;
}
