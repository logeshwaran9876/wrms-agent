namespace WRMS.Agent.Windows;

using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using WRMS.Agent.Configuration;
using WRMS.Agent.Constants;

/// <summary>
/// Manages domain resolution blocking by writing isolated, marked entries into the Windows hosts file.
/// All WRMS entries are bounded between explicit markers to guarantee non-destructive reversal.
/// </summary>
public sealed class HostsFileManager : IHostsFileManager
{
    private readonly ILogger<HostsFileManager> _logger;
    private readonly PolicySettings _settings;
    private readonly SemaphoreSlim _fileLock = new(1, 1);

    [DllImport("dnsapi.dll", EntryPoint = "DnsFlushResolverCache", SetLastError = true)]
    private static extern int DnsFlushResolverCache();

    public HostsFileManager(
        ILogger<HostsFileManager> logger,
        IOptions<PolicySettings> settings)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        _settings = settings?.Value ?? new PolicySettings();
    }

    public async Task ApplyBlocksAsync(IReadOnlyCollection<string> domains, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await _fileLock.WaitAsync(cancellationToken);

        try
        {
            var hostsPath = _settings.HostsFilePath;
            _logger.LogInformation("Applying {Count} blocked domain entries to hosts file: {Path}", domains.Count, hostsPath);

            var originalLines = await ReadAllLinesSafelyAsync(hostsPath, cancellationToken);
            var sanitizedLines = FilterOutWrmsBlockSection(originalLines);

            if (domains.Count > 0)
            {
                sanitizedLines.Add(PolicyConstants.Hosts.BlockMarkerStart);
                sanitizedLines.Add($"# Managed by WRMS Agent. Last modified: {DateTimeOffset.UtcNow:O}");

                foreach (var domain in domains.Distinct(StringComparer.OrdinalIgnoreCase).OrderBy(d => d))
                {
                    sanitizedLines.Add($"{_settings.BlockAddress} {domain}");
                    sanitizedLines.Add($"{PolicyConstants.Hosts.BlockAddressIpv6} {domain}");
                }

                sanitizedLines.Add(PolicyConstants.Hosts.BlockMarkerEnd);
            }

            await WriteLinesSafelyAsync(hostsPath, sanitizedLines, cancellationToken);
            FlushDnsCache();
            _logger.LogInformation("Hosts file updated successfully with {Count} blocked entries.", domains.Count);
        }
        finally
        {
            _fileLock.Release();
        }
    }

    public async Task RemoveBlocksAsync(IReadOnlyCollection<string>? domains, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await _fileLock.WaitAsync(cancellationToken);

        try
        {
            var hostsPath = _settings.HostsFilePath;
            _logger.LogInformation("Removing WRMS block entries from hosts file: {Path}", hostsPath);

            var originalLines = await ReadAllLinesSafelyAsync(hostsPath, cancellationToken);

            if (domains == null || domains.Count == 0)
            {
                // Remove the entire WRMS section
                var sanitizedLines = FilterOutWrmsBlockSection(originalLines);
                await WriteLinesSafelyAsync(hostsPath, sanitizedLines, cancellationToken);
            }
            else
            {
                // Remove only the specified domains while keeping other WRMS-managed domains
                var currentBlocked = ExtractWrmsBlockedDomains(originalLines);
                var toRemove = new HashSet<string>(domains, StringComparer.OrdinalIgnoreCase);
                var remaining = currentBlocked.Where(d => !toRemove.Contains(d)).ToList();

                var sanitizedLines = FilterOutWrmsBlockSection(originalLines);
                if (remaining.Count > 0)
                {
                    sanitizedLines.Add(PolicyConstants.Hosts.BlockMarkerStart);
                    sanitizedLines.Add($"# Managed by WRMS Agent. Last modified: {DateTimeOffset.UtcNow:O}");
                    foreach (var domain in remaining.OrderBy(d => d))
                    {
                        sanitizedLines.Add($"{_settings.BlockAddress} {domain}");
                        sanitizedLines.Add($"{PolicyConstants.Hosts.BlockAddressIpv6} {domain}");
                    }
                    sanitizedLines.Add(PolicyConstants.Hosts.BlockMarkerEnd);
                }

                await WriteLinesSafelyAsync(hostsPath, sanitizedLines, cancellationToken);
            }

            FlushDnsCache();
            _logger.LogInformation("WRMS block entries removed successfully from hosts file.");
        }
        finally
        {
            _fileLock.Release();
        }
    }

    public async Task<IReadOnlyCollection<string>> GetCurrentlyBlockedDomainsAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        await _fileLock.WaitAsync(cancellationToken);

        try
        {
            var originalLines = await ReadAllLinesSafelyAsync(_settings.HostsFilePath, cancellationToken);
            return ExtractWrmsBlockedDomains(originalLines);
        }
        finally
        {
            _fileLock.Release();
        }
    }

    private static List<string> FilterOutWrmsBlockSection(List<string> lines)
    {
        var result = new List<string>(lines.Count);
        var insideWrmsSection = false;

        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (trimmed.Equals(PolicyConstants.Hosts.BlockMarkerStart, StringComparison.OrdinalIgnoreCase))
            {
                insideWrmsSection = true;
                continue;
            }

            if (trimmed.Equals(PolicyConstants.Hosts.BlockMarkerEnd, StringComparison.OrdinalIgnoreCase))
            {
                insideWrmsSection = false;
                continue;
            }

            if (!insideWrmsSection)
            {
                result.Add(line);
            }
        }

        return result;
    }

    private static List<string> ExtractWrmsBlockedDomains(List<string> lines)
    {
        var domains = new List<string>();
        var insideWrmsSection = false;

        foreach (var line in lines)
        {
            var trimmed = line.Trim();
            if (trimmed.Equals(PolicyConstants.Hosts.BlockMarkerStart, StringComparison.OrdinalIgnoreCase))
            {
                insideWrmsSection = true;
                continue;
            }

            if (trimmed.Equals(PolicyConstants.Hosts.BlockMarkerEnd, StringComparison.OrdinalIgnoreCase))
            {
                insideWrmsSection = false;
                continue;
            }

            if (insideWrmsSection && !string.IsNullOrWhiteSpace(trimmed) && !trimmed.StartsWith('#'))
            {
                var parts = trimmed.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2)
                {
                    domains.Add(parts[1]);
                }
            }
        }

        return domains.Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private async Task<List<string>> ReadAllLinesSafelyAsync(string filePath, CancellationToken cancellationToken)
    {
        if (!File.Exists(filePath))
        {
            return [];
        }

        using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new StreamReader(stream, Encoding.UTF8);

        var lines = new List<string>();
        while (await reader.ReadLineAsync(cancellationToken) is { } line)
        {
            lines.Add(line);
        }

        return lines;
    }

    private async Task WriteLinesSafelyAsync(string filePath, List<string> lines, CancellationToken cancellationToken)
    {
        var directory = Path.GetDirectoryName(filePath);
        if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
        {
            Directory.CreateDirectory(directory);
        }

        // Create a safety backup before modifying
        var backupPath = filePath + ".wrms.bak";
        if (File.Exists(filePath) && !File.Exists(backupPath))
        {
            try
            {
                File.Copy(filePath, backupPath, overwrite: true);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not create backup file at {BackupPath}", backupPath);
            }
        }

        // Write directly to file path so directory inheritance and permissions are preserved
        await using (var stream = new FileStream(filePath, FileMode.Create, FileAccess.Write, FileShare.Read))
        await using (var writer = new StreamWriter(stream, new UTF8Encoding(false)))
        {
            foreach (var line in lines)
            {
                await writer.WriteLineAsync(line.AsMemory(), cancellationToken);
            }
        }

        // Explicitly guarantee Read access for Builtin Users and System Services
        if (OperatingSystem.IsWindows())
        {
            try
            {
                var fileInfo = new FileInfo(filePath);
                var acl = fileInfo.GetAccessControl();
                acl.SetAccessRuleProtection(isProtected: false, preserveInheritance: true);

                var usersSid = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);
                acl.AddAccessRule(new FileSystemAccessRule(
                    usersSid,
                    FileSystemRights.ReadAndExecute,
                    AccessControlType.Allow));

                fileInfo.SetAccessControl(acl);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to ensure Builtin\\Users read permissions on hosts file.");
            }
        }
    }

    private void FlushDnsCache()
    {
        if (!OperatingSystem.IsWindows()) return;

        try
        {
            var result = DnsFlushResolverCache();
            _logger.LogDebug("Windows DNS resolver cache flushed via native API. Return code: {Code}", result);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to flush Windows DNS resolver cache via native API.");
        }

        // Also trigger ipconfig /flushdns as a belt-and-suspenders measure for all local resolvers
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "ipconfig.exe",
                Arguments = "/flushdns",
                CreateNoWindow = true,
                UseShellExecute = false
            };
            using var proc = Process.Start(psi);
            proc?.WaitForExit(3000);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "ipconfig /flushdns command execution skipped or timed out.");
        }
    }
}

