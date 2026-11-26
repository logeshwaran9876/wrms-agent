namespace WRMS.Agent.Services;

using WRMS.Agent.Models;

/// <summary>
/// Resolves physical device location using Windows OS Geolocation (GPS/Wi-Fi triangulation)
/// with reverse geocoding and multi-provider IP/ISP fallback.
/// </summary>
public interface IGeoLocationService
{
    /// <summary>
    /// Captures location inside the active user desktop session (where Windows Location privacy consent applies)
    /// and saves the latest reading to shared telemetry storage.
    /// </summary>
    Task<DeviceLocation?> CaptureAndPersistUserSessionLocationAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Resolves the best available public IP and accurate device location for backend reporting.
    /// </summary>
    Task<(string PublicIp, DeviceLocation? Location)> ResolveBestLocationAsync(CancellationToken cancellationToken);
}
