namespace WRMS.Agent.Services;

using Microsoft.Extensions.Logging;
using Microsoft.Win32;
using WRMS.Agent.Models;
using WRMS.Agent.Windows;

/// <summary>
/// Enterprise USB mass storage policy enforcement engine.
/// Operates strictly on USB mass storage devices without impacting input peripherals (mice, keyboards, webcams).
///
/// Implements dual-layer enforcement:
/// 1. USBSTOR service control (HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR\Start = 4 to block, 3 to allow)
/// 2. RemovableStorageDevices & StorageDevicePolicies (WriteProtect = 1 for true Read-Only mode, Deny_All for block)
/// </summary>
public sealed class UsbPolicyService : IUsbPolicyService
{
    private readonly ILogger<UsbPolicyService> _logger;
    private readonly IWindowsRegistryService _registryService;

    private const string UsbStorSubKey = @"SYSTEM\CurrentControlSet\Services\USBSTOR";
    private const string StorageDevicePoliciesSubKey = @"SYSTEM\CurrentControlSet\Control\StorageDevicePolicies";
    private const string RemovableStorageKey = @"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices";
    private const string RemovableDisksGuidKey = @"SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}";
    private const string WrmsManagedValue = "WRMS_Managed";

    public UsbPolicyService(
        ILogger<UsbPolicyService> logger,
        IWindowsRegistryService registryService)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _registryService = registryService ?? throw new ArgumentNullException(nameof(registryService));
    }

    public async Task<(bool Success, List<PolicyRuleResult> Rules, List<string> Errors)> ApplyAsync(
        UsbRule? usbRule,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var rules = new List<PolicyRuleResult>();
        var errors = new List<string>();

        var action = (usbRule?.Action ?? "allow").Trim().ToLowerInvariant();
        if (usbRule?.Block == true) action = "block";
        else if (usbRule?.ReadOnly == true) action = "read_only";

        try
        {
            switch (action)
            {
                case "block":
                    await EnforceBlockAsync(cancellationToken);
                    rules.Add(PolicyRuleResult.Succeeded("USB", "MassStorage", "USB mass storage blocked (USBSTOR=4, RemovableStorageDevices Deny_All=1). Keyboards/mice unaffected."));
                    _logger.LogInformation("USB mass storage enforcement: BLOCKED. Keyboards and mice remain operational.");
                    break;

                case "read_only":
                    await EnforceReadOnlyAsync(cancellationToken);
                    rules.Add(PolicyRuleResult.Succeeded("USB", "MassStorage", "USB mass storage set to READ-ONLY (WriteProtect=1, Deny_Write=1). Files can be opened/read; copying to USB is blocked."));
                    _logger.LogInformation("USB mass storage enforcement: READ-ONLY. Files can be opened/read; writing to USB is blocked.");
                    break;

                case "allow":
                default:
                    await EnforceAllowAsync(cancellationToken);
                    rules.Add(PolicyRuleResult.Succeeded("USB", "MassStorage", "USB mass storage access ALLOWED (Full read/write permitted)."));
                    _logger.LogInformation("USB mass storage enforcement: ALLOWED. Full read/write enabled.");
                    break;
            }

            return (true, rules, errors);
        }
        catch (Exception ex)
        {
            var msg = $"Failed to apply USB storage policy ({action}): {ex.Message}";
            _logger.LogError(ex, msg);
            errors.Add(msg);
            rules.Add(PolicyRuleResult.Failed("USB", "MassStorage", msg));
            return (false, rules, errors);
        }
    }

    public async Task<(bool Success, List<PolicyRuleResult> Rules, List<string> Errors)> RemoveAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var rules = new List<PolicyRuleResult>();
        var errors = new List<string>();

        try
        {
            await EnforceAllowAsync(cancellationToken);
            rules.Add(PolicyRuleResult.Succeeded("USB", "MassStorage", "USB storage policies reverted to system default (Allowed)."));
            return (true, rules, errors);
        }
        catch (Exception ex)
        {
            var msg = $"Failed to revert USB storage policy: {ex.Message}";
            _logger.LogError(ex, msg);
            errors.Add(msg);
            rules.Add(PolicyRuleResult.Failed("USB", "MassStorage", msg));
            return (false, rules, errors);
        }
    }

    public async Task<string> GetCurrentUsbStatusAsync(CancellationToken cancellationToken)
    {
        try
        {
            var usbStorStart = await _registryService.GetDWordValueAsync(RegistryHive.LocalMachine, UsbStorSubKey, "Start", cancellationToken);
            if (usbStorStart == 4)
            {
                return "block";
            }

            var writeProtect = await _registryService.GetDWordValueAsync(RegistryHive.LocalMachine, StorageDevicePoliciesSubKey, "WriteProtect", cancellationToken);
            if (writeProtect == 1)
            {
                return "read_only";
            }

            var denyWrite = await _registryService.GetDWordValueAsync(RegistryHive.LocalMachine, RemovableDisksGuidKey, "Deny_Write", cancellationToken);
            if (denyWrite == 1)
            {
                return "read_only";
            }

            return "allow";
        }
        catch
        {
            return "unknown";
        }
    }

    private async Task EnforceBlockAsync(CancellationToken cancellationToken)
    {
        // 1. Disable USB Mass Storage driver (USBSTOR) -> Value 4 = Disabled
        await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, UsbStorSubKey, "Start", 4, cancellationToken);
        await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, UsbStorSubKey, WrmsManagedValue, 1, cancellationToken);

        // 2. Machine RemovableStorageDevices policy: Deny_All = 1
        await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, RemovableStorageKey, "Deny_All", 1, cancellationToken);
        await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, RemovableStorageKey, WrmsManagedValue, 1, cancellationToken);

        // 3. Removable Disks GUID: Deny_Read = 1, Deny_Write = 1, Deny_Execute = 1
        await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, RemovableDisksGuidKey, "Deny_Read", 1, cancellationToken);
        await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, RemovableDisksGuidKey, "Deny_Write", 1, cancellationToken);
        await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, RemovableDisksGuidKey, "Deny_Execute", 1, cancellationToken);

        // User-level policy mirror
        try
        {
            await _registryService.SetDWordValueAsync(RegistryHive.CurrentUser, RemovableStorageKey, "Deny_All", 1, cancellationToken);
            await _registryService.SetDWordValueAsync(RegistryHive.CurrentUser, RemovableDisksGuidKey, "Deny_Read", 1, cancellationToken);
            await _registryService.SetDWordValueAsync(RegistryHive.CurrentUser, RemovableDisksGuidKey, "Deny_Write", 1, cancellationToken);
            await _registryService.SetDWordValueAsync(RegistryHive.CurrentUser, RemovableDisksGuidKey, "Deny_Execute", 1, cancellationToken);
        }
        catch
        {
            // Ignore current user hive failure in service context
        }

        // Clean up WriteProtect key so read_only doesn't conflict
        try
        {
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, StorageDevicePoliciesSubKey, "WriteProtect", cancellationToken);
        }
        catch
        {
            // Ignore
        }

        BroadcastSystemStoragePolicyChange();
    }

    private async Task EnforceReadOnlyAsync(CancellationToken cancellationToken)
    {
        // 1. Enable USB Mass Storage driver so device can mount -> Value 3 = Manual / Started
        await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, UsbStorSubKey, "Start", 3, cancellationToken);

        // 2. Hardware / Driver Storage Write Protect -> Value 1 = Enabled
        await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, StorageDevicePoliciesSubKey, "WriteProtect", 1, cancellationToken);
        await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, StorageDevicePoliciesSubKey, WrmsManagedValue, 1, cancellationToken);

        // 3. Remove Deny_All so disk mounts
        try
        {
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, RemovableStorageKey, "Deny_All", cancellationToken);
            await _registryService.DeleteValueAsync(RegistryHive.CurrentUser, RemovableStorageKey, "Deny_All", cancellationToken);
        }
        catch
        {
            // Ignore
        }

        // 4. Removable Disks GUID: Allow Read & Execute, Deny Write
        await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, RemovableDisksGuidKey, "Deny_Read", cancellationToken);
        await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, RemovableDisksGuidKey, "Deny_Execute", cancellationToken);
        await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, RemovableDisksGuidKey, "Deny_Write", 1, cancellationToken);
        await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, RemovableDisksGuidKey, WrmsManagedValue, 1, cancellationToken);

        // User-level policy mirror
        try
        {
            await _registryService.DeleteValueAsync(RegistryHive.CurrentUser, RemovableDisksGuidKey, "Deny_Read", cancellationToken);
            await _registryService.DeleteValueAsync(RegistryHive.CurrentUser, RemovableDisksGuidKey, "Deny_Execute", cancellationToken);
            await _registryService.SetDWordValueAsync(RegistryHive.CurrentUser, RemovableDisksGuidKey, "Deny_Write", 1, cancellationToken);
        }
        catch
        {
            // Ignore current user hive failure in service context
        }

        BroadcastSystemStoragePolicyChange();
    }

    private async Task EnforceAllowAsync(CancellationToken cancellationToken)
    {
        // 1. Ensure USBSTOR is enabled (3 = Manual)
        await _registryService.SetDWordValueAsync(RegistryHive.LocalMachine, UsbStorSubKey, "Start", 3, cancellationToken);
        try
        {
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, UsbStorSubKey, WrmsManagedValue, cancellationToken);
        }
        catch { }

        // 2. Remove WriteProtect
        try
        {
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, StorageDevicePoliciesSubKey, "WriteProtect", cancellationToken);
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, StorageDevicePoliciesSubKey, WrmsManagedValue, cancellationToken);
        }
        catch { }

        // 3. Remove Deny_All
        try
        {
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, RemovableStorageKey, "Deny_All", cancellationToken);
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, RemovableStorageKey, WrmsManagedValue, cancellationToken);
            await _registryService.DeleteValueAsync(RegistryHive.CurrentUser, RemovableStorageKey, "Deny_All", cancellationToken);
        }
        catch { }

        // 4. Remove Removable Disks GUID restrictions
        try
        {
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, RemovableDisksGuidKey, "Deny_Read", cancellationToken);
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, RemovableDisksGuidKey, "Deny_Write", cancellationToken);
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, RemovableDisksGuidKey, "Deny_Execute", cancellationToken);
            await _registryService.DeleteValueAsync(RegistryHive.LocalMachine, RemovableDisksGuidKey, WrmsManagedValue, cancellationToken);

            await _registryService.DeleteValueAsync(RegistryHive.CurrentUser, RemovableDisksGuidKey, "Deny_Read", cancellationToken);
            await _registryService.DeleteValueAsync(RegistryHive.CurrentUser, RemovableDisksGuidKey, "Deny_Write", cancellationToken);
            await _registryService.DeleteValueAsync(RegistryHive.CurrentUser, RemovableDisksGuidKey, "Deny_Execute", cancellationToken);
        }
        catch { }

        BroadcastSystemStoragePolicyChange();
    }

    [System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Auto)]
    private static extern IntPtr SendMessageTimeout(
        IntPtr hWnd,
        uint Msg,
        UIntPtr wParam,
        string lParam,
        uint fuFlags,
        uint uTimeout,
        out UIntPtr lpdwResult);

    [System.Runtime.InteropServices.DllImport("shell32.dll")]
    private static extern void SHChangeNotify(int wEventId, uint uFlags, IntPtr dwItem1, IntPtr dwItem2);

    private const uint HWND_BROADCAST = 0xFFFF;
    private const uint WM_SETTINGCHANGE = 0x001A;
    private const uint SMTO_ABORTIFHUNG = 0x0002;
    private const int SHCNE_ASSOCCHANGED = 0x08000000;
    private const uint SHCNF_FLUSH = 0x1000;

    private void BroadcastSystemStoragePolicyChange()
    {
        try
        {
            SendMessageTimeout((IntPtr)HWND_BROADCAST, WM_SETTINGCHANGE, UIntPtr.Zero, "Policy", SMTO_ABORTIFHUNG, 1000, out _);
            SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_FLUSH, IntPtr.Zero, IntPtr.Zero);
            _logger.LogDebug("Windows Shell refreshed with updated storage policy.");
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Failed to broadcast WM_SETTINGCHANGE to Windows shell.");
        }
    }
}
