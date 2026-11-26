namespace WRMS.Agent.Security;

using System.Security.Principal;
using Microsoft.Extensions.Logging;

/// <summary>
/// Verifies Windows administrative privileges using WindowsPrincipal role verification.
/// </summary>
public sealed class PrivilegeService : IPrivilegeService
{
    private readonly ILogger<PrivilegeService> _logger;

    public PrivilegeService(ILogger<PrivilegeService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public bool IsRunningAsAdministrator()
    {
        if (!OperatingSystem.IsWindows())
        {
            _logger.LogWarning("Current OS is not Windows. Privilege check returned false.");
            return false;
        }

        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            var principal = new WindowsPrincipal(identity);
            var isAdmin = principal.IsInRole(WindowsBuiltInRole.Administrator);

            _logger.LogDebug("Privilege verification: IsAdministrator = {IsAdmin}", isAdmin);
            return isAdmin;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to inspect process WindowsIdentity privileges.");
            return false;
        }
    }
}

