namespace WRMS.Agent.Api;

using Microsoft.Extensions.Logging;
using WRMS.Agent.Models;

public sealed class MockAgentApiClient : IAgentApiClient
{
    private readonly ILogger<MockAgentApiClient> _logger;

    public MockAgentApiClient(ILogger<MockAgentApiClient> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public Task<bool> RegisterAsync(DeviceInfo deviceInfo, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(true);
    }

    public Task<Policy?> GetPolicyAsync(string deviceId, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult<Policy?>(null);
    }

    public Task ReportPolicyResultAsync(string deviceId, PolicyApplyResult result, DeviceInfo? deviceInfo, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.CompletedTask;
    }

    public Task<bool> SyncSoftwareAsync(string deviceId, List<InstalledSoftwareInfo> software, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(true);
    }

    public Task<bool> SyncDailyUsageAsync(string deviceId, DailyAppUsageSummary summary, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        return Task.FromResult(true);
    }
}
