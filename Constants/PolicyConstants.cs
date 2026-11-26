namespace WRMS.Agent.Constants;

/// <summary>
/// Centralized constant definitions used throughout WRMS Agent.
/// Eliminates magic strings and numbers across registry, hosts, and policy modules.
/// </summary>
public static class PolicyConstants
{
    public static class Registry
    {
        // 1. Google Chrome policies
        public const string ChromePoliciesSubKey = @"SOFTWARE\Policies\Google\Chrome";
        public const string ChromeIncognitoValueName = "IncognitoModeAvailability";
        public const string ChromeUrlBlocklistSubKey = @"SOFTWARE\Policies\Google\Chrome\URLBlocklist";
        public const string ChromeExtensionBlocklistSubKey = @"SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist";

        // 2. Brave Browser policies
        public const string BravePoliciesSubKey = @"SOFTWARE\Policies\BraveSoftware\Brave";
        public const string BraveTorValueName = "TorDisabled";
        public const string BraveExtensionBlocklistSubKey = @"SOFTWARE\Policies\BraveSoftware\Brave\ExtensionInstallBlocklist";

        // 3. Mozilla Firefox policies
        public const string FirefoxPoliciesSubKey = @"SOFTWARE\Policies\Mozilla\Firefox";
        public const string FirefoxPrivateValueName = "DisablePrivateBrowsing";
        public const string FirefoxBlockAddonsValueName = "BlockAboutAddons";

        // 4. Microsoft Edge policies
        public const string EdgePoliciesSubKey = @"SOFTWARE\Policies\Microsoft\Edge";
        public const string EdgeInPrivateValueName = "InPrivateModeAvailability";
        public const string EdgeUrlBlocklistSubKey = @"SOFTWARE\Policies\Microsoft\Edge\URLBlocklist";
        public const string EdgeExtensionBlocklistSubKey = @"SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist";

        // 5. Opera & Chromium policies
        public const string OperaPoliciesSubKey = @"SOFTWARE\Policies\Opera";
        public const string OperaExtensionBlocklistSubKey = @"SOFTWARE\Policies\Opera\ExtensionInstallBlocklist";
        public const string ChromiumPoliciesSubKey = @"SOFTWARE\Policies\Chromium";
        public const string ChromiumExtensionBlocklistSubKey = @"SOFTWARE\Policies\Chromium\ExtensionInstallBlocklist";

        // Incognito availability values
        public const int IncognitoModeAvailable = 0;
        public const int IncognitoModeDisabled = 1;

        // Secure DNS (DoH) and QUIC bypass mitigation
        public const string DnsOverHttpsModeValueName = "DnsOverHttpsMode";
        public const string DnsOverHttpsModeOff = "off";
        public const string QuicAllowedValueName = "QuicAllowed";
        public const int QuicDisabledValue = 0;

        // Custom WRMS marker tag
        public const string ExplorerPoliciesSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer";
        public const string DisallowRunValueName = "DisallowRun";
        public const string DisallowRunSubKey = @"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\DisallowRun";

        // Custom WRMS marker tag to ensure we only revert values set by WRMS
        public const string WrmsOwnershipTagValueName = "WRMS_Managed";
        public const int WrmsOwnershipValue = 1;
    }

    public static class Hosts
    {
        public const string DefaultHostsFilePath = @"C:\Windows\System32\drivers\etc\hosts";
        public const string BlockAddress = "0.0.0.0";
        public const string BlockAddressIpv6 = "::";
        public const string BlockMarkerStart = "# --- WRMS-AGENT-MANAGED-BLOCKS-START ---";
        public const string BlockMarkerEnd = "# --- WRMS-AGENT-MANAGED-BLOCKS-END ---";
    }

    public static class Statuses
    {
        public const string Success = "Success";
        public const string PartialSuccess = "PartialSuccess";
        public const string Failed = "Failed";
        public const string Unsupported = "Unsupported";
        public const string Skipped = "Skipped";
        public const string NoChangeRequired = "NoChangeRequired";
    }
}

