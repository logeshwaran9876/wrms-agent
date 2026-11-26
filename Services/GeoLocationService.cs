namespace WRMS.Agent.Services;

using System.Globalization;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using WRMS.Agent.Models;

/// <summary>
/// High-accuracy workstation geolocation provider combining Windows 10/11 OS Geolocation
/// (Wi-Fi/GPS/Cellular via WinRT Geolocator), reverse geocoding, and multi-provider IP/ISP resolution.
/// </summary>
public sealed class GeoLocationService : IGeoLocationService
{
    private readonly ILogger<GeoLocationService> _logger;
    private readonly HttpClient _httpClient;

    private static readonly string LocationFilePath = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "WRMS.Agent",
        "usage",
        "location.json");

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    public GeoLocationService(ILogger<GeoLocationService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _httpClient = new HttpClient { Timeout = TimeSpan.FromSeconds(5) };
        _httpClient.DefaultRequestHeaders.UserAgent.ParseAdd("WRMS-Agent/1.0");
    }

    public async Task<DeviceLocation?> CaptureAndPersistUserSessionLocationAsync(CancellationToken cancellationToken)
    {
        var osLoc = await TryGetWindowsOsLocationAsync(cancellationToken);
        var (publicIp, ipLoc) = await ResolveGeoIpFallbackAsync(cancellationToken);

        DeviceLocation? best = null;
        bool hasPreciseFix = osLoc != null &&
                             osLoc.AccuracyMeters.HasValue &&
                             osLoc.AccuracyMeters.Value <= 5000 &&
                             !string.IsNullOrWhiteSpace(osLoc.City);

        if (hasPreciseFix && osLoc != null)
        {
            best = osLoc;
            if (ipLoc != null && !string.IsNullOrWhiteSpace(ipLoc.Isp))
            {
                best.Isp = ipLoc.Isp;
            }
        }
        else if (ipLoc != null)
        {
            best = ipLoc;
            if (osLoc != null && osLoc.Latitude.HasValue && osLoc.Longitude.HasValue)
            {
                // Keep ISP city if OS also only had IP-level precision, or merge finer metadata
                if (string.IsNullOrWhiteSpace(best.City) && !string.IsNullOrWhiteSpace(osLoc.City))
                {
                    best.City = osLoc.City;
                    best.Region = osLoc.Region;
                    best.Country = osLoc.Country;
                    best.CountryCode = osLoc.CountryCode;
                }
            }
        }
        else if (osLoc != null)
        {
            best = osLoc;
        }

        if (best != null)
        {
            best.UpdatedAt = DateTime.UtcNow.ToString("o");
            PersistSharedLocation(new SharedLocationPayload
            {
                PublicIp = publicIp,
                Location = best
            });
        }

        return best;
    }

    public async Task<(string PublicIp, DeviceLocation? Location)> ResolveBestLocationAsync(CancellationToken cancellationToken)
    {
        // 1. Check fresh location persisted by user-session tracker (within last 6 minutes)
        var shared = ReadFreshSharedLocation(TimeSpan.FromMinutes(6));
        if (shared?.Location != null)
        {
            return (shared.PublicIp ?? string.Empty, shared.Location);
        }

        // 2. Fallback: capture directly (works in interactive console or via OS + GeoIP in Service mode)
        var loc = await CaptureAndPersistUserSessionLocationAsync(cancellationToken);
        var saved = ReadFreshSharedLocation(TimeSpan.FromMinutes(6));
        return (saved?.PublicIp ?? string.Empty, loc ?? saved?.Location);
    }

    private async Task<DeviceLocation?> TryGetWindowsOsLocationAsync(CancellationToken cancellationToken)
    {
        if (!OperatingSystem.IsWindowsVersionAtLeast(10, 0, 19041))
        {
            return null;
        }

        try
        {
            var geolocator = new global::Windows.Devices.Geolocation.Geolocator
            {
                DesiredAccuracy = global::Windows.Devices.Geolocation.PositionAccuracy.High
            };

            var pos = await geolocator.GetGeopositionAsync(
                TimeSpan.FromSeconds(15),
                TimeSpan.FromSeconds(6)).AsTask(cancellationToken);

            var coord = pos?.Coordinate;
            if (coord == null) return null;

            double lat = coord.Point.Position.Latitude;
            double lon = coord.Point.Position.Longitude;
            double acc = coord.Accuracy;
            string posSrc = coord.PositionSource.ToString();

            var sourceLabel = coord.PositionSource == global::Windows.Devices.Geolocation.PositionSource.IPAddress
                ? "Windows OS (IP)"
                : $"Windows OS ({posSrc})";

            var reverse = await ReverseGeocodeAsync(lat, lon, cancellationToken);
            return new DeviceLocation
            {
                City = reverse?.City ?? string.Empty,
                Region = reverse?.Region ?? string.Empty,
                Country = reverse?.Country ?? string.Empty,
                CountryCode = reverse?.CountryCode ?? string.Empty,
                Latitude = Math.Round(lat, 6),
                Longitude = Math.Round(lon, 6),
                AccuracyMeters = Math.Round(acc, 1),
                Source = sourceLabel,
                UpdatedAt = DateTime.UtcNow.ToString("o")
            };
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Windows OS Geolocator unavailable in current session context.");
            return null;
        }
    }

    private async Task<DeviceLocation?> ReverseGeocodeAsync(double lat, double lon, CancellationToken cancellationToken)
    {
        string latStr = lat.ToString("F6", CultureInfo.InvariantCulture);
        string lonStr = lon.ToString("F6", CultureInfo.InvariantCulture);

        // Primary reverse geocode: BigDataCloud (fast, free, reliable city/locality extraction)
        try
        {
            var bdcUrl = $"https://api.bigdatacloud.net/data/reverse-geocode-client?latitude={latStr}&longitude={lonStr}&localityLanguage=en";
            var res = await _httpClient.GetAsync(bdcUrl, cancellationToken);
            if (res.IsSuccessStatusCode)
            {
                var json = await res.Content.ReadAsStringAsync(cancellationToken);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                string city = GetStringProp(root, "city");
                if (string.IsNullOrWhiteSpace(city)) city = GetStringProp(root, "locality");

                if (!string.IsNullOrWhiteSpace(city))
                {
                    return new DeviceLocation
                    {
                        City = city,
                        Region = GetStringProp(root, "principalSubdivision"),
                        Country = GetStringProp(root, "countryName"),
                        CountryCode = GetStringProp(root, "countryCode")
                    };
                }
            }
        }
        catch { }

        // Backup reverse geocode: OpenStreetMap Nominatim
        try
        {
            var nomUrl = $"https://nominatim.openstreetmap.org/reverse?format=jsonv2&lat={latStr}&lon={lonStr}&zoom=10";
            var res = await _httpClient.GetAsync(nomUrl, cancellationToken);
            if (res.IsSuccessStatusCode)
            {
                var json = await res.Content.ReadAsStringAsync(cancellationToken);
                using var doc = JsonDocument.Parse(json);
                if (doc.RootElement.TryGetProperty("address", out var addr))
                {
                    string city = GetStringProp(addr, "city");
                    if (string.IsNullOrWhiteSpace(city)) city = GetStringProp(addr, "town");
                    if (string.IsNullOrWhiteSpace(city)) city = GetStringProp(addr, "municipality");
                    if (string.IsNullOrWhiteSpace(city)) city = GetStringProp(addr, "state_district").Replace(" District", "", StringComparison.OrdinalIgnoreCase).Trim();
                    if (string.IsNullOrWhiteSpace(city)) city = GetStringProp(addr, "county").Replace(" District", "", StringComparison.OrdinalIgnoreCase).Trim();

                    return new DeviceLocation
                    {
                        City = city,
                        Region = GetStringProp(addr, "state"),
                        Country = GetStringProp(addr, "country"),
                        CountryCode = GetStringProp(addr, "country_code").ToUpperInvariant()
                    };
                }
            }
        }
        catch { }

        return null;
    }

    private async Task<(string PublicIp, DeviceLocation? Location)> ResolveGeoIpFallbackAsync(CancellationToken cancellationToken)
    {
        // Try ipwho.is first (supports HTTPS, detailed ISP/region/coordinates), then ipinfo.io, then ip-api.com
        try
        {
            var res = await _httpClient.GetAsync("https://ipwho.is/", cancellationToken);
            if (res.IsSuccessStatusCode)
            {
                var json = await res.Content.ReadAsStringAsync(cancellationToken);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                if (root.TryGetProperty("success", out var ok) && ok.GetBoolean())
                {
                    string ip = GetStringProp(root, "ip");
                    string isp = root.TryGetProperty("connection", out var conn) ? GetStringProp(conn, "isp") : string.Empty;
                    double? lat = root.TryGetProperty("latitude", out var latEl) && latEl.TryGetDouble(out var dLat) ? dLat : null;
                    double? lon = root.TryGetProperty("longitude", out var lonEl) && lonEl.TryGetDouble(out var dLon) ? dLon : null;

                    return (ip, new DeviceLocation
                    {
                        City = GetStringProp(root, "city"),
                        Region = GetStringProp(root, "region"),
                        Country = GetStringProp(root, "country"),
                        CountryCode = GetStringProp(root, "country_code"),
                        Isp = isp,
                        Latitude = lat,
                        Longitude = lon,
                        AccuracyMeters = 25000,
                        Source = "IP Geolocation (ISP)"
                    });
                }
            }
        }
        catch { }

        try
        {
            var res = await _httpClient.GetAsync("https://ipinfo.io/json", cancellationToken);
            if (res.IsSuccessStatusCode)
            {
                var json = await res.Content.ReadAsStringAsync(cancellationToken);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                string ip = GetStringProp(root, "ip");
                string locStr = GetStringProp(root, "loc");
                double? lat = null, lon = null;
                var parts = locStr.Split(',');
                if (parts.Length == 2 &&
                    double.TryParse(parts[0], NumberStyles.Float, CultureInfo.InvariantCulture, out var parsedLat) &&
                    double.TryParse(parts[1], NumberStyles.Float, CultureInfo.InvariantCulture, out var parsedLon))
                {
                    lat = parsedLat;
                    lon = parsedLon;
                }

                string cc = GetStringProp(root, "country");
                return (ip, new DeviceLocation
                {
                    City = GetStringProp(root, "city"),
                    Region = GetStringProp(root, "region"),
                    Country = cc == "IN" ? "India" : cc,
                    CountryCode = cc,
                    Isp = GetStringProp(root, "org"),
                    Latitude = lat,
                    Longitude = lon,
                    AccuracyMeters = 25000,
                    Source = "IP Geolocation (ISP)"
                });
            }
        }
        catch { }

        try
        {
            var res = await _httpClient.GetAsync("http://ip-api.com/json", cancellationToken);
            if (res.IsSuccessStatusCode)
            {
                var json = await res.Content.ReadAsStringAsync(cancellationToken);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                if (GetStringProp(root, "status") == "success")
                {
                    double? lat = root.TryGetProperty("lat", out var latEl) && latEl.TryGetDouble(out var dLat) ? dLat : null;
                    double? lon = root.TryGetProperty("lon", out var lonEl) && lonEl.TryGetDouble(out var dLon) ? dLon : null;

                    return (GetStringProp(root, "query"), new DeviceLocation
                    {
                        City = GetStringProp(root, "city"),
                        Region = GetStringProp(root, "regionName"),
                        Country = GetStringProp(root, "country"),
                        CountryCode = GetStringProp(root, "countryCode"),
                        Isp = GetStringProp(root, "isp"),
                        Latitude = lat,
                        Longitude = lon,
                        AccuracyMeters = 50000,
                        Source = "IP Geolocation (ISP)"
                    });
                }
            }
        }
        catch { }

        return (string.Empty, null);
    }

    private static string GetStringProp(JsonElement element, string name)
    {
        return element.TryGetProperty(name, out var prop) && prop.ValueKind == JsonValueKind.String
            ? (prop.GetString()?.Trim() ?? string.Empty)
            : string.Empty;
    }

    private static SharedLocationPayload? ReadFreshSharedLocation(TimeSpan maxAge)
    {
        try
        {
            if (!File.Exists(LocationFilePath)) return null;
            var json = File.ReadAllText(LocationFilePath);
            var payload = JsonSerializer.Deserialize<SharedLocationPayload>(json, JsonOptions);
            if (payload?.Location == null) return null;

            if (DateTimeOffset.TryParse(payload.Location.UpdatedAt, out var updatedAt) &&
                (DateTimeOffset.UtcNow - updatedAt) <= maxAge)
            {
                return payload;
            }
        }
        catch { }
        return null;
    }

    private static void PersistSharedLocation(SharedLocationPayload payload)
    {
        try
        {
            var dir = Path.GetDirectoryName(LocationFilePath);
            if (!string.IsNullOrEmpty(dir)) Directory.CreateDirectory(dir);
            var tmp = LocationFilePath + ".tmp";
            File.WriteAllText(tmp, JsonSerializer.Serialize(payload, JsonOptions));
            File.Move(tmp, LocationFilePath, overwrite: true);
        }
        catch { }
    }

    private sealed class SharedLocationPayload
    {
        public string? PublicIp { get; set; }
        public DeviceLocation? Location { get; set; }
    }
}
