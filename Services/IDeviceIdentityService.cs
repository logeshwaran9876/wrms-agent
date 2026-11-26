namespace WRMS.Agent.Services;

using WRMS.Agent.Models;

/// <summary>
/// Retrieves stable hardware and operating system identity for the host machine.
/// Does not gather user personal data, files, or surveillance metrics.
/// </summary>
public interface IDeviceIdentityService
{
    /// <summary>
    /// Gets the stable identity information for the local device.
    /// Throttles heavy port and software scans to 1-hour intervals unless forceScan is requested.
    /// </summary>
    Task<DeviceInfo> GetDeviceInfoAsync(CancellationToken cancellationToken, bool forceScan = false);
}

