namespace WRMS.Agent.Models;

/// <summary>
/// Machine identification and live security telemetry model.
/// Contains network interfaces, public IP, geo-location, firewall posture, active listening ports, and software inventory.
/// </summary>
public sealed class DeviceInfo
{
    public string DeviceId { get; set; } = string.Empty;
    public string ComputerName { get; set; } = string.Empty;
    public string EmployeeName { get; set; } = string.Empty;
    public string WindowsVersion { get; set; } = string.Empty;
    public string AgentVersion { get; set; } = string.Empty;
    public string IpAddress { get; set; } = "127.0.0.1";
    public string PublicIp { get; set; } = string.Empty;
    public string MacAddress { get; set; } = string.Empty;
    public DeviceLocation? Location { get; set; }
    public string FirewallStatus { get; set; } = "enabled";
    public bool FirewallEnabled { get; set; } = true;
    public List<OpenPortInfo> OpenPorts { get; set; } = [];
    public List<InstalledSoftwareInfo> SoftwareList { get; set; } = [];
    public bool PortsScannedFresh { get; set; } = false;
    public bool SoftwareScannedFresh { get; set; } = false;
    public DateTimeOffset RetrievedAt { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class DeviceLocation
{
    public string City { get; set; } = string.Empty;
    public string Region { get; set; } = string.Empty;
    public string Country { get; set; } = string.Empty;
    public string CountryCode { get; set; } = string.Empty;
    public string Isp { get; set; } = string.Empty;
    public double? Latitude { get; set; }
    public double? Longitude { get; set; }
    public double? AccuracyMeters { get; set; }
    public string Source { get; set; } = string.Empty;
    public string UpdatedAt { get; set; } = string.Empty;
}
