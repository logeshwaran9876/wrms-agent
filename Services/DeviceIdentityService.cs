namespace WRMS.Agent.Services;

using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Win32;
using WRMS.Agent.Configuration;
using WRMS.Agent.Models;

/// <summary>
/// Implements stable, non-invasive device identification.
/// Uses the Windows system MachineGuid to maintain a persistent identity across reboots and service restarts.
/// </summary>
public sealed class DeviceIdentityService : IDeviceIdentityService
{
    private readonly ILogger<DeviceIdentityService> _logger;
    private readonly AgentSettings _settings;
    private readonly IFirewallInspectorService _firewallInspector;
    private readonly IPortScannerService _portScanner;
    private readonly ISoftwareInventoryService _softwareInventory;
    private readonly IForegroundUsageTracker _usageTracker;
    private readonly IGeoLocationService _geoLocationService;
    private DeviceInfo? _cachedDeviceInfo;
    private List<OpenPortInfo> _cachedOpenPorts = [];
    private DateTimeOffset _lastPortScanTime = DateTimeOffset.MinValue;
    private List<InstalledSoftwareInfo> _cachedSoftwareList = [];
    private DateTimeOffset _lastSoftwareScanTime = DateTimeOffset.MinValue;
    private (string publicIp, DeviceLocation? location) _cachedGeoLocation = (string.Empty, null);
    private DateTimeOffset _lastGeoScanTime = DateTimeOffset.MinValue;
    private string _lastLocalIp = string.Empty;
    private readonly SemaphoreSlim _lock = new(1, 1);

    public DeviceIdentityService(
        ILogger<DeviceIdentityService> logger,
        IOptions<AgentSettings> settings,
        IFirewallInspectorService firewallInspector,
        IPortScannerService portScanner,
        ISoftwareInventoryService softwareInventory,
        IForegroundUsageTracker usageTracker,
        IGeoLocationService geoLocationService)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _settings = settings?.Value ?? throw new ArgumentNullException(nameof(settings));
        _firewallInspector = firewallInspector ?? throw new ArgumentNullException(nameof(firewallInspector));
        _portScanner = portScanner ?? throw new ArgumentNullException(nameof(portScanner));
        _softwareInventory = softwareInventory ?? throw new ArgumentNullException(nameof(softwareInventory));
        _usageTracker = usageTracker ?? throw new ArgumentNullException(nameof(usageTracker));
        _geoLocationService = geoLocationService ?? throw new ArgumentNullException(nameof(geoLocationService));
    }

    public async Task<DeviceInfo> GetDeviceInfoAsync(CancellationToken cancellationToken, bool forceScan = false)
    {
        await _lock.WaitAsync(cancellationToken);
        try
        {
            var deviceId = GetStableDeviceId();
            var computerName = Environment.MachineName;
            var employeeName = ResolveHumanEmployeeName();
            var windowsVersion = Environment.OSVersion.VersionString;

            // Live fast security telemetry
            var (localIp, mac) = ResolveLocalNetworkDetails();
            var (fwStatus, fwEnabled, _, _, _) = _firewallInspector.GetFirewallStatus();

            // Periodic 1-hour interval for heavy inventory scans, and frequent 5-minute interval (or network change) for geolocation
            var scanInterval = TimeSpan.FromHours(Math.Max(1, _settings.TelemetryScanIntervalHours));
            var geoInterval = TimeSpan.FromMinutes(5);
            var now = DateTimeOffset.UtcNow;
            bool networkChanged = !string.IsNullOrEmpty(_lastLocalIp) && !string.Equals(_lastLocalIp, localIp, StringComparison.OrdinalIgnoreCase);
            _lastLocalIp = localIp;

            // 1. Geo-location lookup (every 5 minutes or immediately on network change)
            if (forceScan || networkChanged || _lastGeoScanTime == DateTimeOffset.MinValue || (now - _lastGeoScanTime) >= geoInterval)
            {
                _cachedGeoLocation = await _geoLocationService.ResolveBestLocationAsync(cancellationToken);
                _lastGeoScanTime = now;
            }

            // 2. Open listening ports scan (throttle to 1 hour, runs once on install/startup)
            bool portsScannedFresh = false;
            if (forceScan || _lastPortScanTime == DateTimeOffset.MinValue || (now - _lastPortScanTime) >= scanInterval)
            {
                _cachedOpenPorts = _portScanner.GetActiveListeningPorts();
                _lastPortScanTime = now;
                portsScannedFresh = true;
                _logger.LogInformation(
                    "[PORT SCANNER] Telemetry refreshed: {Count} active listening ports identified ({Reason}).",
                    _cachedOpenPorts.Count,
                    _cachedDeviceInfo == null ? "Initial Startup / Installation" : "Periodic 1-Hour Cycle");
            }

            // 3. Installed software registry scan (throttle to 1 hour, runs once on install/startup)
            bool softwareScannedFresh = false;
            if (forceScan || _lastSoftwareScanTime == DateTimeOffset.MinValue || (now - _lastSoftwareScanTime) >= scanInterval)
            {
                _cachedSoftwareList = _softwareInventory.GetInstalledSoftware();
                _lastSoftwareScanTime = now;
                softwareScannedFresh = true;
                _logger.LogInformation(
                    "[SOFTWARE INVENTORY] Telemetry refreshed: {Count} installed applications discovered ({Reason}).",
                    _cachedSoftwareList.Count,
                    _cachedDeviceInfo == null ? "Initial Startup / Installation" : "Periodic 1-Hour Cycle");
            }
            else
            {
                // Refresh execution counts cleanly from today's exact tracked app usage + UserAssist
                var dailyUsage = _usageTracker.ReadDailySummary();
                _softwareInventory.RefreshExecutionCounts(_cachedSoftwareList, dailyUsage);
            }

            _cachedDeviceInfo = new DeviceInfo
            {
                DeviceId = deviceId,
                ComputerName = computerName,
                EmployeeName = employeeName,
                WindowsVersion = windowsVersion,
                AgentVersion = _settings.AgentVersion,
                IpAddress = localIp,
                PublicIp = _cachedGeoLocation.publicIp,
                MacAddress = mac,
                Location = _cachedGeoLocation.location,
                FirewallStatus = fwStatus,
                FirewallEnabled = fwEnabled,
                OpenPorts = _cachedOpenPorts,
                SoftwareList = _cachedSoftwareList,
                PortsScannedFresh = portsScannedFresh,
                SoftwareScannedFresh = softwareScannedFresh,
                RetrievedAt = now
            };

            if (portsScannedFresh || softwareScannedFresh)
            {
                _logger.LogInformation(
                    "Device full telemetry updated: DeviceId = {DeviceId}, FW = {FW}, Ports = {Ports} (Fresh={FreshPorts}), Software = {Software} (Fresh={FreshSw})",
                    _cachedDeviceInfo.DeviceId,
                    _cachedDeviceInfo.FirewallStatus,
                    _cachedDeviceInfo.OpenPorts.Count,
                    portsScannedFresh,
                    _cachedDeviceInfo.SoftwareList.Count,
                    softwareScannedFresh);
            }

            return _cachedDeviceInfo;
        }
        finally
        {
            _lock.Release();
        }
    }

    private static (string ip, string mac) ResolveLocalNetworkDetails()
    {
        string localIp = "127.0.0.1";
        string mac = "";

        try
        {
            var interfaces = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces()
                .Where(nic => nic.OperationalStatus == System.Net.NetworkInformation.OperationalStatus.Up &&
                              nic.NetworkInterfaceType != System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
                .ToList();

            foreach (var nic in interfaces)
            {
                var props = nic.GetIPProperties();
                var ip = props.UnicastAddresses
                    .FirstOrDefault(a => a.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork &&
                                        !System.Net.IPAddress.IsLoopback(a.Address));

                if (ip != null)
                {
                    localIp = ip.Address.ToString();
                    mac = string.Join(":", nic.GetPhysicalAddress().GetAddressBytes().Select(b => b.ToString("X2")));
                    break;
                }
            }
        }
        catch { }

        return (localIp, mac);
    }

    private string GetStableDeviceId()
    {
        if (!OperatingSystem.IsWindows())
        {
            return $"NON-WIN-{Environment.MachineName}";
        }

        try
        {
            // Standard Windows MachineGuid from HKLM\SOFTWARE\Microsoft\Cryptography
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var cryptoKey = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
            var guid = cryptoKey?.GetValue("MachineGuid")?.ToString();

            if (!string.IsNullOrWhiteSpace(guid))
            {
                return $"WRMS-DEV-{guid.Trim()}";
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to read MachineGuid from registry. Attempting fallback storage.");
        }

        // Fallback: check or persist device id in local AppData
        return GetOrCreateLocalFallbackId();
    }

    private string GetOrCreateLocalFallbackId()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        var stateDir = Path.Combine(appData, "WRMS.Agent");
        var idFile = Path.Combine(stateDir, "device.id");

        try
        {
            if (File.Exists(idFile))
            {
                var existingId = File.ReadAllText(idFile).Trim();
                if (!string.IsNullOrWhiteSpace(existingId))
                {
                    return existingId;
                }
            }

            Directory.CreateDirectory(stateDir);
            var newId = $"WRMS-DEV-{Guid.NewGuid():D}";
            File.WriteAllText(idFile, newId);
            return newId;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to read/write fallback device ID. Generating session ID.");
            return $"WRMS-DEV-SESSION-{Guid.NewGuid():D}";
        }
    }

    [DllImport("wtsapi32.dll", SetLastError = true)]
    private static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("wtsapi32.dll", SetLastError = true, CharSet = CharSet.Auto)]
    private static extern bool WTSQuerySessionInformation(
        IntPtr hServer,
        uint sessionId,
        int wtsInfoClass,
        out IntPtr ppBuffer,
        out uint pBytesReturned);

    [DllImport("wtsapi32.dll")]
    private static extern void WTSFreeMemory(IntPtr pMemory);

    private string ResolveHumanEmployeeName()
    {
        // 1. Dynamic Live Console Session User via Windows Terminal Services (WTS API)
        // Works reliably even when running under NT AUTHORITY\SYSTEM as a Windows Service
        try
        {
            uint consoleSessionId = WTSGetActiveConsoleSessionId();
            if (consoleSessionId != 0xFFFFFFFF)
            {
                IntPtr pBuffer = IntPtr.Zero;
                uint bytesReturned = 0;
                // WTSUserName = 5
                if (WTSQuerySessionInformation(IntPtr.Zero, consoleSessionId, 5, out pBuffer, out bytesReturned) && pBuffer != IntPtr.Zero)
                {
                    try
                    {
                        string? sessionUser = Marshal.PtrToStringAuto(pBuffer)?.Trim();
                        if (!string.IsNullOrWhiteSpace(sessionUser) &&
                            !sessionUser.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) &&
                            !sessionUser.Equals("LOCAL SERVICE", StringComparison.OrdinalIgnoreCase) &&
                            !sessionUser.Equals("NETWORK SERVICE", StringComparison.OrdinalIgnoreCase) &&
                            !sessionUser.EndsWith("$"))
                        {
                            var fullDisplay = TryGetDisplayNameFromLogonUI();
                            if (!string.IsNullOrWhiteSpace(fullDisplay))
                            {
                                return fullDisplay;
                            }
                            return sessionUser;
                        }
                    }
                    finally
                    {
                        WTSFreeMemory(pBuffer);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "WTS session query for active user encountered an exception.");
        }

        // 2. From Registry LogonUI (LastLoggedOnDisplayName or LastLoggedOnSAMUser / LastLoggedOnUser)
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var logonKey = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI");
            if (logonKey != null)
            {
                var displayName = logonKey.GetValue("LastLoggedOnDisplayName")?.ToString()?.Trim();
                if (!string.IsNullOrWhiteSpace(displayName) &&
                    !displayName.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) &&
                    !displayName.EndsWith("$"))
                {
                    return displayName;
                }

                var samUser = logonKey.GetValue("LastLoggedOnSAMUser")?.ToString()?.Trim()
                           ?? logonKey.GetValue("LastLoggedOnUser")?.ToString()?.Trim();
                if (!string.IsNullOrWhiteSpace(samUser))
                {
                    int slashIdx = samUser.LastIndexOf('\\');
                    if (slashIdx >= 0) samUser = samUser.Substring(slashIdx + 1).Trim();
                    if (!string.IsNullOrWhiteSpace(samUser) &&
                        !samUser.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) &&
                        !samUser.EndsWith("$"))
                    {
                        return samUser;
                    }
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "LogonUI registry query encountered an exception.");
        }

        // 3. Interactive Environment UserName
        var envUser = Environment.UserName;
        if (!string.IsNullOrWhiteSpace(envUser) &&
            !envUser.EndsWith("$") &&
            !envUser.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) &&
            !envUser.Equals("LOCAL SERVICE", StringComparison.OrdinalIgnoreCase) &&
            !envUser.Equals("NETWORK SERVICE", StringComparison.OrdinalIgnoreCase))
        {
            return envUser;
        }

        // 4. From WRMS Registry enrollment HKLM\SOFTWARE\WRMS (only if not legacy default)
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var wrmsKey = baseKey.OpenSubKey(@"SOFTWARE\WRMS");
            var regEmp = wrmsKey?.GetValue("EmployeeName")?.ToString()?.Trim();
            if (!string.IsNullOrWhiteSpace(regEmp) &&
                !regEmp.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) &&
                !regEmp.EndsWith("$"))
            {
                return regEmp;
            }
        }
        catch { }

        // 5. From strongly-typed AgentSettings (appsettings.json)
        if (!string.IsNullOrWhiteSpace(_settings.EmployeeName) &&
            !_settings.EmployeeName.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) &&
            !_settings.EmployeeName.EndsWith("$"))
        {
            return _settings.EmployeeName.Trim();
        }

        // 6. Dynamic Machine fallback: MachineName User (Never hardcode static names)
        return $"{Environment.MachineName} User";
    }

    private static string? TryGetDisplayNameFromLogonUI()
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64);
            using var logonKey = baseKey.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI");
            if (logonKey != null)
            {
                var displayName = logonKey.GetValue("LastLoggedOnDisplayName")?.ToString()?.Trim();
                if (!string.IsNullOrWhiteSpace(displayName) &&
                    !displayName.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase) &&
                    !displayName.EndsWith("$"))
                {
                    return displayName;
                }
            }
        }
        catch { }
        return null;
    }
}

