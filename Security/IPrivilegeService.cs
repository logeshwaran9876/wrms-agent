namespace WRMS.Agent.Security;

/// <summary>
/// Service to determine whether the running process has elevated administrative rights.
/// </summary>
public interface IPrivilegeService
{
    /// <summary>
    /// Checks if the process runs with Windows Administrator / LocalSystem privileges.
    /// </summary>
    bool IsRunningAsAdministrator();
}

