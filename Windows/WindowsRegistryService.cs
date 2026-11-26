namespace WRMS.Agent.Windows;

using Microsoft.Extensions.Logging;
using Microsoft.Win32;

/// <summary>
/// Safe, asynchronous wrapper over Windows Registry operations.
/// Encapsulates hive resolution, key disposal, and error logging.
/// </summary>
public sealed class WindowsRegistryService : IWindowsRegistryService
{
    private readonly ILogger<WindowsRegistryService> _logger;

    public WindowsRegistryService(ILogger<WindowsRegistryService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public Task SetDWordValueAsync(RegistryHive hive, string subKey, string valueName, int value, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            using var targetKey = baseKey.CreateSubKey(subKey, writable: true);

            if (targetKey == null)
            {
                throw new InvalidOperationException($"Unable to open or create registry subkey '{subKey}' in hive '{hive}'.");
            }

            targetKey.SetValue(valueName, value, RegistryValueKind.DWord);
            _logger.LogInformation("Registry value set successfully: [{Hive}\\{SubKey}] {ValueName} = {Value} (REG_DWORD)",
                hive, subKey, valueName, value);

            return Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to set registry value: [{Hive}\\{SubKey}] {ValueName}", hive, subKey, valueName);
            throw;
        }
    }

    public Task SetStringValueAsync(RegistryHive hive, string subKey, string valueName, string value, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            using var targetKey = baseKey.CreateSubKey(subKey, writable: true);

            if (targetKey == null)
            {
                throw new InvalidOperationException($"Unable to open or create registry subkey '{subKey}' in hive '{hive}'.");
            }

            targetKey.SetValue(valueName, value, RegistryValueKind.String);
            _logger.LogInformation("Registry value set successfully: [{Hive}\\{SubKey}] {ValueName} = {Value} (REG_SZ)",
                hive, subKey, valueName, value);

            return Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to set registry string value: [{Hive}\\{SubKey}] {ValueName}", hive, subKey, valueName);
            throw;
        }
    }

    public Task DeleteSubKeyTreeAsync(RegistryHive hive, string subKey, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            baseKey.DeleteSubKeyTree(subKey, throwOnMissingSubKey: false);
            _logger.LogInformation("Registry subkey tree deleted successfully: [{Hive}\\{SubKey}]", hive, subKey);
            return Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to delete registry subkey tree: [{Hive}\\{SubKey}]", hive, subKey);
            throw;
        }
    }

    public Task<int?> GetDWordValueAsync(RegistryHive hive, string subKey, string valueName, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            using var targetKey = baseKey.OpenSubKey(subKey, writable: false);

            if (targetKey == null)
            {
                return Task.FromResult<int?>(null);
            }

            var rawValue = targetKey.GetValue(valueName);
            if (rawValue is int intValue)
            {
                return Task.FromResult<int?>(intValue);
            }

            if (rawValue != null && int.TryParse(rawValue.ToString(), out var parsedValue))
            {
                return Task.FromResult<int?>(parsedValue);
            }

            return Task.FromResult<int?>(null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to read registry value: [{Hive}\\{SubKey}] {ValueName}", hive, subKey, valueName);
            throw;
        }
    }

    public Task DeleteValueAsync(RegistryHive hive, string subKey, string valueName, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            using var targetKey = baseKey.OpenSubKey(subKey, writable: true);

            if (targetKey != null)
            {
                targetKey.DeleteValue(valueName, throwOnMissingValue: false);
                _logger.LogInformation("Registry value deleted successfully: [{Hive}\\{SubKey}] {ValueName}",
                    hive, subKey, valueName);
            }

            return Task.CompletedTask;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to delete registry value: [{Hive}\\{SubKey}] {ValueName}", hive, subKey, valueName);
            throw;
        }
    }

    public Task<bool> ValueExistsAsync(RegistryHive hive, string subKey, string valueName, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            using var targetKey = baseKey.OpenSubKey(subKey, writable: false);

            if (targetKey == null)
            {
                return Task.FromResult(false);
            }

            var value = targetKey.GetValue(valueName);
            return Task.FromResult(value != null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to check registry value existence: [{Hive}\\{SubKey}] {ValueName}", hive, subKey, valueName);
            throw;
        }
    }

    public Task<bool> SubKeyExistsAsync(RegistryHive hive, string subKey, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Default);
            using var targetKey = baseKey.OpenSubKey(subKey, writable: false);

            return Task.FromResult(targetKey != null);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to check registry subkey existence: [{Hive}\\{SubKey}]", hive, subKey);
            throw;
        }
    }
}

