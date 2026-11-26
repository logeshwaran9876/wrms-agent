namespace WRMS.Agent.Services;

using WRMS.Agent.Models;

/// <summary>
/// Enforces enterprise USB mass storage restrictions via Windows registry policies.
/// Supports Block, Read-Only, and Allow states without interfering with keyboards, mice, or other HID devices.
/// </summary>
public interface IUsbPolicyService
{
    Task<(bool Success, List<PolicyRuleResult> Rules, List<string> Errors)> ApplyAsync(UsbRule? usbRule, CancellationToken cancellationToken);

    Task<(bool Success, List<PolicyRuleResult> Rules, List<string> Errors)> RemoveAsync(CancellationToken cancellationToken);

    Task<string> GetCurrentUsbStatusAsync(CancellationToken cancellationToken);
}
