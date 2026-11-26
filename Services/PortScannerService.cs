namespace WRMS.Agent.Services;

using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Microsoft.Extensions.Logging;
using WRMS.Agent.Models;

/// <summary>
/// Native high-performance socket scanner.
/// Discovers open listening TCP and UDP endpoints and correlates them with the
/// active executing Windows application / process using the Windows IP Helper API (iphlpapi.dll).
/// </summary>
public sealed class PortScannerService : IPortScannerService
{
    private readonly ILogger<PortScannerService> _logger;

    public PortScannerService(ILogger<PortScannerService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));
    }

    public List<OpenPortInfo> GetActiveListeningPorts()
    {
        var result = new List<OpenPortInfo>();
        var seen = new HashSet<(int, string)>();

        // 1. Attempt deep Windows IP Helper scan with PID & Process Name resolution
        if (OperatingSystem.IsWindows())
        {
            try
            {
                ScanExtendedTcpPorts(result, seen);
                ScanExtendedUdpPorts(result, seen);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Extended IP Helper socket scan failed; falling back to IPGlobalProperties.");
            }
        }

        // 2. Fallback / supplement with IPGlobalProperties
        try
        {
            var properties = IPGlobalProperties.GetIPGlobalProperties();

            // TCP Active Listeners fallback
            var tcpEndpoints = properties.GetActiveTcpListeners();
            foreach (var ep in tcpEndpoints)
            {
                if (ep.Port > 0 && seen.Add((ep.Port, "TCP")))
                {
                    result.Add(new OpenPortInfo
                    {
                        Port = ep.Port,
                        Protocol = "TCP",
                        ProcessName = ResolveCommonPortService(ep.Port),
                        IsAllowed = true
                    });
                }
            }

            // UDP Active Listeners fallback
            var udpEndpoints = properties.GetActiveUdpListeners();
            foreach (var ep in udpEndpoints)
            {
                if (ep.Port > 0 && seen.Add((ep.Port, "UDP")))
                {
                    result.Add(new OpenPortInfo
                    {
                        Port = ep.Port,
                        Protocol = "UDP",
                        ProcessName = ResolveCommonPortService(ep.Port),
                        IsAllowed = true
                    });
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to scan active listening ports.");
        }

        result = result.OrderBy(p => p.Port).ToList();

        Console.WriteLine($"[DEBUG-PORTS] Scanned {result.Count} active listening ports with bound application telemetry.");
        foreach (var p in result.Take(5))
        {
            Console.WriteLine($"   -> Port {p.Port}/{p.Protocol}: {p.ProcessName}");
        }

        return result;
    }

    private void ScanExtendedTcpPorts(List<OpenPortInfo> result, HashSet<(int, string)> seen)
    {
        // Scan IPv4 TCP
        ScanTcpTable(AF_INET, result, seen);
        // Scan IPv6 TCP
        ScanTcp6Table(AF_INET6, result, seen);
    }

    private void ScanExtendedUdpPorts(List<OpenPortInfo> result, HashSet<(int, string)> seen)
    {
        // Scan IPv4 UDP
        ScanUdpTable(AF_INET, result, seen);
        // Scan IPv6 UDP
        ScanUdp6Table(AF_INET6, result, seen);
    }

    private void ScanTcpTable(int af, List<OpenPortInfo> result, HashSet<(int, string)> seen)
    {
        int bufferSize = 0;
        uint ret = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, af, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
        if (bufferSize <= 0) return;

        IntPtr pTable = Marshal.AllocHGlobal(bufferSize);
        try
        {
            ret = GetExtendedTcpTable(pTable, ref bufferSize, true, af, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0) return;

            int numEntries = Marshal.ReadInt32(pTable);
            IntPtr rowPtr = IntPtr.Add(pTable, 4);
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                rowPtr = IntPtr.Add(rowPtr, rowSize);

                // MIB_TCP_STATE_LISTEN = 2
                if (row.state == 2)
                {
                    int port = (row.localPort1 << 8) | row.localPort2;
                    if (port > 0 && seen.Add((port, "TCP")))
                    {
                        var procName = GetProcessNameFromPid(row.owningPid);
                        result.Add(new OpenPortInfo
                        {
                            Port = port,
                            Protocol = "TCP",
                            ProcessName = FormatProcessService(procName, port),
                            IsAllowed = true
                        });
                    }
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pTable);
        }
    }

    private void ScanTcp6Table(int af, List<OpenPortInfo> result, HashSet<(int, string)> seen)
    {
        int bufferSize = 0;
        uint ret = GetExtendedTcpTable(IntPtr.Zero, ref bufferSize, true, af, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
        if (bufferSize <= 0) return;

        IntPtr pTable = Marshal.AllocHGlobal(bufferSize);
        try
        {
            ret = GetExtendedTcpTable(pTable, ref bufferSize, true, af, TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, 0);
            if (ret != 0) return;

            int numEntries = Marshal.ReadInt32(pTable);
            IntPtr rowPtr = IntPtr.Add(pTable, 4);
            int rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr);
                rowPtr = IntPtr.Add(rowPtr, rowSize);

                if (row.state == 2)
                {
                    int port = (row.localPort1 << 8) | row.localPort2;
                    if (port > 0 && seen.Add((port, "TCP")))
                    {
                        var procName = GetProcessNameFromPid(row.owningPid);
                        result.Add(new OpenPortInfo
                        {
                            Port = port,
                            Protocol = "TCP",
                            ProcessName = FormatProcessService(procName, port),
                            IsAllowed = true
                        });
                    }
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pTable);
        }
    }

    private void ScanUdpTable(int af, List<OpenPortInfo> result, HashSet<(int, string)> seen)
    {
        int bufferSize = 0;
        uint ret = GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true, af, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
        if (bufferSize <= 0) return;

        IntPtr pTable = Marshal.AllocHGlobal(bufferSize);
        try
        {
            ret = GetExtendedUdpTable(pTable, ref bufferSize, true, af, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
            if (ret != 0) return;

            int numEntries = Marshal.ReadInt32(pTable);
            IntPtr rowPtr = IntPtr.Add(pTable, 4);
            int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                rowPtr = IntPtr.Add(rowPtr, rowSize);

                int port = (row.localPort1 << 8) | row.localPort2;
                if (port > 0 && seen.Add((port, "UDP")))
                {
                    var procName = GetProcessNameFromPid(row.owningPid);
                    result.Add(new OpenPortInfo
                    {
                        Port = port,
                        Protocol = "UDP",
                        ProcessName = FormatProcessService(procName, port),
                        IsAllowed = true
                    });
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pTable);
        }
    }

    private void ScanUdp6Table(int af, List<OpenPortInfo> result, HashSet<(int, string)> seen)
    {
        int bufferSize = 0;
        uint ret = GetExtendedUdpTable(IntPtr.Zero, ref bufferSize, true, af, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
        if (bufferSize <= 0) return;

        IntPtr pTable = Marshal.AllocHGlobal(bufferSize);
        try
        {
            ret = GetExtendedUdpTable(pTable, ref bufferSize, true, af, UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, 0);
            if (ret != 0) return;

            int numEntries = Marshal.ReadInt32(pTable);
            IntPtr rowPtr = IntPtr.Add(pTable, 4);
            int rowSize = Marshal.SizeOf<MIB_UDP6ROW_OWNER_PID>();

            for (int i = 0; i < numEntries; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDP6ROW_OWNER_PID>(rowPtr);
                rowPtr = IntPtr.Add(rowPtr, rowSize);

                int port = (row.localPort1 << 8) | row.localPort2;
                if (port > 0 && seen.Add((port, "UDP")))
                {
                    var procName = GetProcessNameFromPid(row.owningPid);
                    result.Add(new OpenPortInfo
                    {
                        Port = port,
                        Protocol = "UDP",
                        ProcessName = FormatProcessService(procName, port),
                        IsAllowed = true
                    });
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pTable);
        }
    }

    private static string GetProcessNameFromPid(uint pid)
    {
        if (pid == 0) return "System Idle";
        if (pid == 4) return "System Kernel";
        try
        {
            using var proc = Process.GetProcessById((int)pid);
            var name = proc.ProcessName;
            if (!string.IsNullOrWhiteSpace(name))
            {
                return $"{name}.exe";
            }
        }
        catch { }
        return $"PID {pid}";
    }

    private static string FormatProcessService(string procName, int port)
    {
        var common = ResolveCommonPortService(port);
        if (string.IsNullOrEmpty(procName) || procName.StartsWith("PID ", StringComparison.OrdinalIgnoreCase))
        {
            return common;
        }

        if (common != "Listening Service")
        {
            return $"{procName} ({common})";
        }

        return procName;
    }

    private static string ResolveCommonPortService(int port)
    {
        return port switch
        {
            80 => "HTTP (World Wide Web)",
            443 => "HTTPS (Secure Web)",
            53 => "DNS (Domain Name Service)",
            123 => "NTP (Network Time Protocol)",
            22 => "SSH (Secure Shell)",
            21 => "FTP (File Transfer Protocol)",
            25 => "SMTP (Email Routing)",
            110 => "POP3 (Email Retrieval)",
            143 => "IMAP (Mail Access)",
            3389 => "RDP (Remote Desktop)",
            445 => "SMB (Windows File Sharing)",
            135 => "RPC (Remote Procedure Call)",
            139 => "NetBIOS",
            8080 => "HTTP Alternate / Proxy",
            8443 => "HTTPS Alternate",
            3000 => "Dev Server (Node.js)",
            5000 => "Dev Server (WRMS / .NET)",
            5173 => "Dev Server (Vite HMR)",
            27017 => "MongoDB Database",
            3306 => "MySQL Database",
            5432 => "PostgreSQL Database",
            6379 => "Redis Cache",
            _ => "Listening Service"
        };
    }

    private const int AF_INET = 2;
    private const int AF_INET6 = 23;

    private enum TCP_TABLE_CLASS
    {
        TCP_TABLE_BASIC_LISTENER,
        TCP_TABLE_BASIC_CONNECTIONS,
        TCP_TABLE_BASIC_ALL,
        TCP_TABLE_OWNER_PID_LISTENER,
        TCP_TABLE_OWNER_PID_CONNECTIONS,
        TCP_TABLE_OWNER_PID_ALL,
        TCP_TABLE_OWNER_MODULE_LISTENER,
        TCP_TABLE_OWNER_MODULE_CONNECTIONS,
        TCP_TABLE_OWNER_MODULE_ALL
    }

    private enum UDP_TABLE_CLASS
    {
        UDP_TABLE_BASIC,
        UDP_TABLE_OWNER_PID,
        UDP_TABLE_OWNER_MODULE
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint state;
        public uint localAddr;
        public byte localPort1;
        public byte localPort2;
        public byte localPort3;
        public byte localPort4;
        public uint remoteAddr;
        public byte remotePort1;
        public byte remotePort2;
        public byte remotePort3;
        public byte remotePort4;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;
        public uint localScopeId;
        public byte localPort1;
        public byte localPort2;
        public byte localPort3;
        public byte localPort4;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] remoteAddr;
        public uint remoteScopeId;
        public byte remotePort1;
        public byte remotePort2;
        public byte remotePort3;
        public byte remotePort4;
        public uint state;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint localAddr;
        public byte localPort1;
        public byte localPort2;
        public byte localPort3;
        public byte localPort4;
        public uint owningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] localAddr;
        public uint localScopeId;
        public byte localPort1;
        public byte localPort2;
        public byte localPort3;
        public byte localPort4;
        public uint owningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        TCP_TABLE_CLASS tableClass,
        uint reserved = 0);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        UDP_TABLE_CLASS tableClass,
        uint reserved = 0);
}
