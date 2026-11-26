namespace WRMS.Agent.Api;

using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WRMS.Agent.Configuration;
using WRMS.Agent.Models;

/// <summary>
/// Production REST API client communicating with the WRMS management server (Node.js/Express + MongoDB).
/// Handles device registration, dynamic policy retrieval, and compliance status reporting.
/// </summary>
public sealed class AgentApiClient : IAgentApiClient
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<AgentApiClient> _logger;
    private readonly BackendSettings _settings;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    public AgentApiClient(
        HttpClient httpClient,
        ILogger<AgentApiClient> logger,
        IOptions<BackendSettings> settings)
    {
        _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _settings = settings?.Value ?? new BackendSettings();

        // Configure default headers
        if (!string.IsNullOrWhiteSpace(_settings.AgentApiKey))
        {
            if (!_httpClient.DefaultRequestHeaders.Contains("X-Agent-Secret"))
            {
                _httpClient.DefaultRequestHeaders.Add("X-Agent-Secret", _settings.AgentApiKey);
            }
        }
    }

    public async Task<bool> RegisterAsync(DeviceInfo deviceInfo, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            _logger.LogInformation("Registering device {DeviceId} ({ComputerName}) with backend...",
                deviceInfo.DeviceId, deviceInfo.ComputerName);

            var response = await _httpClient.PostAsJsonAsync(
                "api/devices/register",
                deviceInfo,
                JsonOptions,
                cancellationToken);

            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("Device {DeviceId} registered successfully with management server.", deviceInfo.DeviceId);
                return true;
            }
            else
            {
                var content = await response.Content.ReadAsStringAsync(cancellationToken);
                _logger.LogWarning("Device registration returned non-success status: {StatusCode} - {Content}",
                    response.StatusCode, content);
                return false;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Could not reach management server to register device {DeviceId}. Will retry next cycle.", deviceInfo.DeviceId);
            return false;
        }
    }

    public async Task<Policy?> GetPolicyAsync(string deviceId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            _logger.LogInformation("Fetching dynamic policy for device {DeviceId} from {BaseUrl}...",
                deviceId, _httpClient.BaseAddress);

            using var request = new HttpRequestMessage(HttpMethod.Get, $"api/devices/{Uri.EscapeDataString(deviceId)}/policy");
            request.Headers.Add("X-Device-Id", deviceId);

            var response = await _httpClient.SendAsync(request, cancellationToken);

            if (response.StatusCode == System.Net.HttpStatusCode.NotModified)
            {
                _logger.LogDebug("Backend returned 304 Not Modified. Existing policy remains effective.");
                return null;
            }

            if (response.IsSuccessStatusCode)
            {
                var policy = await response.Content.ReadFromJsonAsync<Policy>(JsonOptions, cancellationToken);
                if (policy != null)
                {
                    _logger.LogInformation("Dynamic policy fetched successfully: {PolicyId} v{Version} with {WebCount} website rules.",
                        policy.PolicyId, policy.PolicyVersion, policy.WebsiteRules?.Count ?? 0);
                    return policy;
                }
            }

            _logger.LogWarning("Failed to fetch policy from backend. HTTP Status: {Status}", response.StatusCode);
            return null;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Network error fetching dynamic policy from backend for device {DeviceId}.", deviceId);
            return null;
        }
    }

    public async Task ReportPolicyResultAsync(string deviceId, PolicyApplyResult result, DeviceInfo? deviceInfo, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            _logger.LogInformation("Reporting policy status for {PolicyId} v{Version} (Status: {Status}) to backend...",
                result.PolicyId, result.PolicyVersion, result.Status);

            var payload = new
            {
                result.PolicyId,
                result.PolicyVersion,
                result.Status,
                result.Success,
                result.Rules,
                result.Errors,
                result.AppliedAt,
                IpAddress = deviceInfo?.IpAddress,
                PublicIp = deviceInfo?.PublicIp,
                MacAddress = deviceInfo?.MacAddress,
                Location = deviceInfo?.Location,
                FirewallStatus = deviceInfo?.FirewallStatus,
                FirewallEnabled = deviceInfo?.FirewallEnabled,
                OpenPorts = (deviceInfo?.PortsScannedFresh == true) ? deviceInfo?.OpenPorts : null,
            };

            using var request = new HttpRequestMessage(HttpMethod.Post, $"api/devices/{Uri.EscapeDataString(deviceId)}/policy-status")
            {
                Content = JsonContent.Create(payload, options: JsonOptions)
            };
            request.Headers.Add("X-Device-Id", deviceId);

            var response = await _httpClient.SendAsync(request, cancellationToken);
            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("Policy status acknowledged by server for policy {PolicyId}.", result.PolicyId);
            }
            else
            {
                _logger.LogWarning("Server returned {Status} when acknowledging policy result.", response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to report policy status to backend for device {DeviceId}.", deviceId);
        }
    }

    public async Task<bool> SyncSoftwareAsync(string deviceId, List<InstalledSoftwareInfo> software, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            var freqCount = software.Count(s => s.ExecutionCount > 0);
            var payload = new { softwareList = software };
            using var request = new HttpRequestMessage(HttpMethod.Post, $"api/devices/{Uri.EscapeDataString(deviceId)}/software")
            {
                Content = JsonContent.Create(payload, options: JsonOptions)
            };
            request.Headers.Add("X-Device-Id", deviceId);

            var response = await _httpClient.SendAsync(request, cancellationToken);
            var ok = response.IsSuccessStatusCode;
            Console.WriteLine($"[DEBUG-API] SyncSoftwareAsync -> HTTP {(int)response.StatusCode} ({response.StatusCode}). Synced {software.Count} applications ({freqCount} frequently used) to backend.");
            return ok;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to sync software inventory to backend for device {DeviceId}.", deviceId);
            Console.WriteLine($"[DEBUG-API] SyncSoftwareAsync error: {ex.Message}");
            return false;
        }
    }

    public async Task<bool> SyncDailyUsageAsync(string deviceId, DailyAppUsageSummary summary, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, $"api/devices/{Uri.EscapeDataString(deviceId)}/app-usage")
            {
                Content = JsonContent.Create(summary, options: JsonOptions)
            };
            request.Headers.Add("X-Device-Id", deviceId);

            var response = await _httpClient.SendAsync(request, cancellationToken);
            return response.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to sync daily app usage telemetry to backend for device {DeviceId}.", deviceId);
            return false;
        }
    }
}
