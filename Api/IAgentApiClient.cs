namespace WRMS.Agent.Api;

using WRMS.Agent.Models;

/// <summary>
/// Abstraction for communication with the enterprise WRMS backend API.
/// </summary>
public interface IAgentApiClient
{
    /// <summary>
    /// Registers this Windows agent and device information with the central management server.
    /// </summary>
    Task<bool> RegisterAsync(DeviceInfo deviceInfo, CancellationToken cancellationToken);

    /// <summary>
    /// Fetches the latest assigned policy for this device.
    /// </summary>
    Task<Policy?> GetPolicyAsync(string deviceId, CancellationToken cancellationToken);

    /// <summary>
    /// Reports the result of applying a policy back to the central server with live security telemetry.
    /// </summary>
    Task ReportPolicyResultAsync(string deviceId, PolicyApplyResult result, DeviceInfo? deviceInfo, CancellationToken cancellationToken);

    /// <summary>
    /// Synchronizes the harvested workstation software inventory with the central management server.
    /// </summary>
    Task<bool> SyncSoftwareAsync(string deviceId, List<InstalledSoftwareInfo> software, CancellationToken cancellationToken);

    /// <summary>
    /// Synchronizes accurate daily foreground screen-time and launch telemetry with the central management server.
    /// </summary>
    Task<bool> SyncDailyUsageAsync(string deviceId, DailyAppUsageSummary summary, CancellationToken cancellationToken);
}
