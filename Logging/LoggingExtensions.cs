namespace WRMS.Agent.Logging;

using Microsoft.Extensions.Logging;

/// <summary>
/// Provides high-performance, structured logging extensions for WRMS Agent lifecycle and health events.
/// Uses LoggerMessage.Define to eliminate object allocations and enforce consistent EventIds.
/// </summary>
public static class LoggingExtensions
{
    private static readonly Action<ILogger, string, string, Exception?> ServiceStartingDefinition =
        LoggerMessage.Define<string, string>(
            LogLevel.Information,
            new EventId(1001, nameof(LogServiceStarting)),
            "WRMS Agent starting. Service: {ServiceName}, Version: {Version}");

    private static readonly Action<ILogger, string, int, Exception?> HealthHeartbeatDefinition =
        LoggerMessage.Define<string, int>(
            LogLevel.Information,
            new EventId(1002, nameof(LogHealthHeartbeat)),
            "WRMS Agent health heartbeat [{ServiceName}]. Check interval: {IntervalSeconds}s");

    private static readonly Action<ILogger, string, Exception?> ServiceStoppingDefinition =
        LoggerMessage.Define<string>(
            LogLevel.Information,
            new EventId(1003, nameof(LogServiceStopping)),
            "WRMS Agent stopping gracefully. Service: {ServiceName}");

    private static readonly Action<ILogger, string, Exception?> CycleErrorDefinition =
        LoggerMessage.Define<string>(
            LogLevel.Error,
            new EventId(1004, nameof(LogCycleError)),
            "Unhandled error occurred during agent cycle [{ServiceName}]. The agent will recover and continue running.");

    public static void LogServiceStarting(this ILogger logger, string serviceName, string version) =>
        ServiceStartingDefinition(logger, serviceName, version, null);

    public static void LogHealthHeartbeat(this ILogger logger, string serviceName, int intervalSeconds) =>
        HealthHeartbeatDefinition(logger, serviceName, intervalSeconds, null);

    public static void LogServiceStopping(this ILogger logger, string serviceName) =>
        ServiceStoppingDefinition(logger, serviceName, null);

    public static void LogCycleError(this ILogger logger, string serviceName, Exception ex) =>
        CycleErrorDefinition(logger, serviceName, ex);
}

