namespace WRMS.Agent.Models;

/// <summary>
/// Defines an executable application control rule specifying whether a desktop application is permitted or blocked.
/// </summary>
public sealed class ApplicationRule
{
    public string AppName { get; set; } = string.Empty;

    public string ExecutableName { get; set; } = string.Empty;

    public bool Block { get; set; } = true;
}
