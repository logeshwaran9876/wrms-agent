namespace WRMS.Agent.Windows;

using Microsoft.Win32;

/// <summary>
/// Abstraction for controlled, safe access to the Windows Registry.
/// Prevents scattering direct Microsoft.Win32.Registry calls throughout domain services.
/// </summary>
public interface IWindowsRegistryService
{
    Task SetDWordValueAsync(RegistryHive hive, string subKey, string valueName, int value, CancellationToken cancellationToken);

    Task SetStringValueAsync(RegistryHive hive, string subKey, string valueName, string value, CancellationToken cancellationToken);

    Task<int?> GetDWordValueAsync(RegistryHive hive, string subKey, string valueName, CancellationToken cancellationToken);

    Task DeleteValueAsync(RegistryHive hive, string subKey, string valueName, CancellationToken cancellationToken);

    Task DeleteSubKeyTreeAsync(RegistryHive hive, string subKey, CancellationToken cancellationToken);

    Task<bool> ValueExistsAsync(RegistryHive hive, string subKey, string valueName, CancellationToken cancellationToken);

    Task<bool> SubKeyExistsAsync(RegistryHive hive, string subKey, CancellationToken cancellationToken);
}

