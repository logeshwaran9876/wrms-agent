namespace WRMS.Agent.Models;

/// <summary>
/// Rule governing browser behavior and restrictions on the Windows device across 5 major browsers:
/// Google Chrome, Brave, Mozilla Firefox, Microsoft Edge, and Opera.
/// </summary>
public sealed class BrowserRule
{
    // 1. Google Chrome
    public bool DisableChromePrivate { get; set; } = true;
    public bool BlockChromeExtensions { get; set; } = false;

    // 2. Brave Browser
    public bool DisableBravePrivate { get; set; } = true;
    public bool BlockBraveExtensions { get; set; } = false;

    // 3. Mozilla Firefox
    public bool DisableFirefoxPrivate { get; set; } = true;
    public bool BlockFirefoxExtensions { get; set; } = false;

    // 4. Microsoft Edge
    public bool DisableEdgePrivate { get; set; } = true;
    public bool BlockEdgeExtensions { get; set; } = false;

    // 5. Opera & Opera GX
    public bool DisableOperaPrivate { get; set; } = true;
    public bool BlockOperaExtensions { get; set; } = false;
}
