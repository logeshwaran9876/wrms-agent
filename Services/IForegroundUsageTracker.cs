namespace WRMS.Agent.Services;

using WRMS.Agent.Models;

/// <summary>
/// Tracks true foreground application active focus time, user idle time, and real app launches per day.
/// </summary>
public interface IForegroundUsageTracker
{
    /// <summary>
    /// Ensures the usage directory exists with permissions accessible by the interactive user session tracker.
    /// </summary>
    void EnsureStorageReady();

    /// <summary>
    /// Runs the 1-second foreground + idle tracking loop inside an interactive desktop session.
    /// </summary>
    Task RunSessionLoopAsync(CancellationToken cancellationToken);

    /// <summary>
    /// Reads today's accumulated usage summary from disk for backend synchronization.
    /// </summary>
    DailyAppUsageSummary? ReadDailySummary(string? localDate = null);
}
