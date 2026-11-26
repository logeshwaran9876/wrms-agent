namespace WRMS.Agent.Services;

using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WRMS.Agent.Configuration;
using WRMS.Agent.Constants;
using WRMS.Agent.Models;

/// <summary>
/// Persists and evaluates local policy state to guarantee idempotent policy application.
/// </summary>
public sealed class PolicyStateService : IPolicyStateService
{
    private readonly ILogger<PolicyStateService> _logger;
    private readonly PolicySettings _policySettings;
    private readonly SemaphoreSlim _stateLock = new(1, 1);
    private PolicyState? _inMemoryState;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true
    };

    public PolicyStateService(
        ILogger<PolicyStateService> logger,
        IOptions<PolicySettings> policySettings)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _policySettings = policySettings?.Value ?? new PolicySettings();
    }

    public async Task<PolicyState?> GetCurrentStateAsync(CancellationToken cancellationToken)
    {
        if (_inMemoryState != null)
        {
            return _inMemoryState;
        }

        await _stateLock.WaitAsync(cancellationToken);
        try
        {
            if (_inMemoryState != null)
            {
                return _inMemoryState;
            }

            var filePath = ResolveStateFilePath();
            if (!File.Exists(filePath))
            {
                return null;
            }

            var json = await File.ReadAllTextAsync(filePath, cancellationToken);
            _inMemoryState = JsonSerializer.Deserialize<PolicyState>(json, JsonOptions);
            return _inMemoryState;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load policy state from disk. Starting with empty state.");
            return null;
        }
        finally
        {
            _stateLock.Release();
        }
    }

    public async Task SaveStateAsync(PolicyState state, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await _stateLock.WaitAsync(cancellationToken);

        try
        {
            _inMemoryState = state;
            var filePath = ResolveStateFilePath();
            var directory = Path.GetDirectoryName(filePath);

            if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var json = JsonSerializer.Serialize(state, JsonOptions);
            await File.WriteAllTextAsync(filePath, json, cancellationToken);

            _logger.LogInformation(
                "Policy state persisted: PolicyId = {PolicyId}, Version = {Version}, Status = {Status}",
                state.LastAppliedPolicyId, state.LastAppliedPolicyVersion, state.LastApplyStatus);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to persist policy state to disk.");
        }
        finally
        {
            _stateLock.Release();
        }
    }

    public bool IsPolicyAlreadyApplied(Policy policy, PolicyState? currentState)
    {
        if (currentState == null)
        {
            return false;
        }

        if (!currentState.LastApplyStatus.Equals(PolicyConstants.Statuses.Success, StringComparison.OrdinalIgnoreCase))
        {
            // Previous run was not fully successful; must reapply
            return false;
        }

        if (!currentState.LastAppliedPolicyId.Equals(policy.PolicyId, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        if (currentState.LastAppliedPolicyVersion != policy.PolicyVersion)
        {
            return false;
        }

        // Verify USB storage action consistency
        var targetUsbAction = policy.UsbRule?.Action ?? (policy.UsbRule?.Block == true ? "block" : (policy.UsbRule?.ReadOnly == true ? "read_only" : "allow"));
        if (!string.Equals(currentState.UsbAction, targetUsbAction, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        // Verify Firewall enforcement consistency
        if (policy.EnforceFirewallEnabled.HasValue && currentState.FirewallEnforced != policy.EnforceFirewallEnabled.Value)
        {
            return false;
        }

        return true;
    }

    private string ResolveStateFilePath()
    {
        if (!string.IsNullOrWhiteSpace(_policySettings.StateFilePath))
        {
            return _policySettings.StateFilePath;
        }

        var appData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
        return Path.Combine(appData, "WRMS.Agent", "state.json");
    }
}

