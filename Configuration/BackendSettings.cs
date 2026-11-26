namespace WRMS.Agent.Configuration;

/// <summary>
/// Configuration parameters for backend REST API connectivity and dynamic synchronization.
/// </summary>
public sealed class BackendSettings
{
    public const string SectionName = "Backend";

    /// <summary>
    /// Base URL of the WRMS Management Server (e.g., https://wrms-backend-2m6u.onrender.com or https://api.wrms.corp).
    /// </summary>
    public string ApiBaseUrl { get; set; } = "https://wrms-backend-2m6u.onrender.com";

    /// <summary>
    /// Shared secret or API key for authenticating agent requests against the server.
    /// </summary>
    public string AgentApiKey { get; set; } = "wrms-agent-secret-key-2026";

    /// <summary>
    /// Flag controlling whether the agent fetches policies dynamically from the remote backend.
    /// Default is true for full dynamic management.
    /// </summary>
    public bool UseRemotePolicy { get; set; } = true;

    /// <summary>
    /// Path to the offline fallback policy cache file on disk.
    /// Defaults to %ProgramData%\WRMS.Agent\cached_policy.json.
    /// </summary>
    public string OfflineCacheFilePath { get; set; } = string.Empty;

    /// <summary>
    /// HTTP timeout in seconds for backend communications.
    /// </summary>
    public int RequestTimeoutSeconds { get; set; } = 30;
}
