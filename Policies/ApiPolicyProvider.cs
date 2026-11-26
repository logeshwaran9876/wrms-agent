namespace WRMS.Agent.Policies;

using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WRMS.Agent.Api;
using WRMS.Agent.Configuration;
using WRMS.Agent.Models;
using WRMS.Agent.Services;

/// <summary>
/// Dynamic policy provider fetching rules from the remote WRMS management backend.
/// Incorporates full offline resilience: caches the last valid policy on disk so restrictions
/// remain 100% active even during network outages or server restarts.
/// </summary>
public sealed class ApiPolicyProvider : IPolicyProvider
{
    private readonly ILogger<ApiPolicyProvider> _logger;
    private readonly IAgentApiClient _apiClient;
    private readonly IDeviceIdentityService _deviceIdentityService;
    private readonly IPocPolicyProvider _pocFallbackProvider;
    private readonly BackendSettings _settings;
    private readonly SemaphoreSlim _cacheLock = new(1, 1);

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        WriteIndented = true
    };

    public ApiPolicyProvider(
        ILogger<ApiPolicyProvider> logger,
        IAgentApiClient apiClient,
        IDeviceIdentityService deviceIdentityService,
        IPocPolicyProvider pocFallbackProvider,
        IOptions<BackendSettings> settings)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _apiClient = apiClient ?? throw new ArgumentNullException(nameof(apiClient));
        _deviceIdentityService = deviceIdentityService ?? throw new ArgumentNullException(nameof(deviceIdentityService));
        _pocFallbackProvider = pocFallbackProvider ?? throw new ArgumentNullException(nameof(pocFallbackProvider));
        _settings = settings?.Value ?? new BackendSettings();
    }

    public async Task<Policy?> GetCurrentPolicyAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var deviceInfo = await _deviceIdentityService.GetDeviceInfoAsync(cancellationToken);

        // 1. Fetch dynamic policy directly from remote backend (Primary source of truth)
        try
        {
            var remotePolicy = await _apiClient.GetPolicyAsync(deviceInfo.DeviceId, cancellationToken);
            if (remotePolicy != null)
            {
                _logger.LogInformation("Remote dynamic policy '{PolicyId}' v{Version} loaded with {Count} website rules. Updating offline cache...",
                    remotePolicy.PolicyId, remotePolicy.PolicyVersion, remotePolicy.WebsiteRules?.Count ?? 0);

                await SaveToOfflineCacheAsync(remotePolicy, cancellationToken);
                return remotePolicy;
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to retrieve remote policy from {Url}. Engaging offline cache.", _settings.ApiBaseUrl);
        }

        // 2. OFFLINE RESILIENCE: If server is temporarily unreachable, use last successfully synced dynamic policy
        var cachedPolicy = await LoadFromOfflineCacheAsync(cancellationToken);
        if (cachedPolicy != null)
        {
            _logger.LogInformation("Using offline cached policy '{PolicyId}' v{Version} with {Count} website rules (Server unreachable).",
                cachedPolicy.PolicyId, cachedPolicy.PolicyVersion, cachedPolicy.WebsiteRules?.Count ?? 0);
            return cachedPolicy;
        }

        // 3. Clean dynamic fallback: 0 hardcoded rules (never hardcode static domains!)
        _logger.LogWarning("No remote response and no offline cache available. Engaging clean fallback policy.");
        return await _pocFallbackProvider.GetPolicyAsync(cancellationToken);
    }

    private async Task SaveToOfflineCacheAsync(Policy policy, CancellationToken cancellationToken)
    {
        await _cacheLock.WaitAsync(cancellationToken);
        try
        {
            var path = ResolveCacheFilePath();
            var dir = Path.GetDirectoryName(path);
            if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
            {
                Directory.CreateDirectory(dir);
            }

            var json = JsonSerializer.Serialize(policy, JsonOptions);
            await File.WriteAllTextAsync(path, json, cancellationToken);
            _logger.LogDebug("Offline policy cached at {Path}", path);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to persist offline policy cache.");
        }
        finally
        {
            _cacheLock.Release();
        }
    }

    private async Task<Policy?> LoadFromOfflineCacheAsync(CancellationToken cancellationToken)
    {
        await _cacheLock.WaitAsync(cancellationToken);
        try
        {
            var path = ResolveCacheFilePath();
            if (!File.Exists(path))
            {
                return null;
            }

            var json = await File.ReadAllTextAsync(path, cancellationToken);
            return JsonSerializer.Deserialize<Policy>(json, JsonOptions);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to read offline policy cache file.");
            return null;
        }
        finally
        {
            _cacheLock.Release();
        }
    }

    private string ResolveCacheFilePath()
    {
        if (!string.IsNullOrWhiteSpace(_settings.OfflineCacheFilePath))
        {
            return _settings.OfflineCacheFilePath;
        }

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        return Path.Combine(appData, "WRMS.Agent", "cached_policy.json");
    }
}
