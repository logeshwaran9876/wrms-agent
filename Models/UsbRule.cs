namespace WRMS.Agent.Models;

/// <summary>
/// USB storage control rule specifying whether USB mass storage drives are blocked, read-only, or allowed.
/// Operates strictly at the mass storage device class level and never interferes with keyboards, mice, or HID devices.
/// </summary>
public sealed class UsbRule
{
    public bool Block { get; set; } = false;

    public bool ReadOnly { get; set; } = false;

    public string Action { get; set; } = "allow"; // "allow", "block", "read_only"
}
