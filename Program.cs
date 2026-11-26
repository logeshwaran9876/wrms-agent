using System.Diagnostics;
using System.Security.Principal;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging.EventLog;
using WRMS.Agent;
using WRMS.Agent.Api;
using WRMS.Agent.Configuration;
using WRMS.Agent.Policies;
using WRMS.Agent.Security;
using WRMS.Agent.Services;
using WRMS.Agent.Windows;

// Lightweight user-session foreground usage tracker mode (launched by WRMS.Agent service into active desktop session)
if (args.Contains("--session-tracker"))
{
    using var singleInstance = new Mutex(true, @"Local\WRMS_SessionTracker_Singleton", out bool createdNew);
    if (!createdNew)
    {
        return;
    }

    int? parentPid = null;
    var parentIdx = Array.IndexOf(args, "--parent-pid");
    if (parentIdx >= 0 && parentIdx + 1 < args.Length && int.TryParse(args[parentIdx + 1], out int parsedPid))
    {
        parentPid = parsedPid;
    }

    using var loggerFactory = LoggerFactory.Create(logging => logging.AddConsole());
    var geoService = new GeoLocationService(loggerFactory.CreateLogger<GeoLocationService>());
    var tracker = new ForegroundUsageTracker(loggerFactory.CreateLogger<ForegroundUsageTracker>(), geoService);
    using var cts = new CancellationTokenSource();

    Console.CancelKeyPress += (_, e) =>
    {
        e.Cancel = true;
        cts.Cancel();
    };
    AppDomain.CurrentDomain.ProcessExit += (_, _) => cts.Cancel();

    // Auto-exit if parent Windows Service stops or crashes so no orphan process holds locks
    if (parentPid.HasValue)
    {
        _ = Task.Run(async () =>
        {
            while (!cts.IsCancellationRequested)
            {
                try
                {
                    using var parent = Process.GetProcessById(parentPid.Value);
                    if (parent.HasExited)
                    {
                        cts.Cancel();
                        break;
                    }
                }
                catch
                {
                    cts.Cancel();
                    break;
                }
                await Task.Delay(3000, cts.Token).ConfigureAwait(false);
            }
        });
    }

    await tracker.RunSessionLoopAsync(cts.Token);
    return;
}

// Auto-elevate to Administrator on Windows if running in interactive user session
if (OperatingSystem.IsWindows() && Environment.UserInteractive && !args.Contains("--no-elevate"))
{
    using var identity = WindowsIdentity.GetCurrent();
    var principal = new WindowsPrincipal(identity);
    if (!principal.IsInRole(WindowsBuiltInRole.Administrator))
    {
        try
        {
            var exePath = Environment.ProcessPath ?? Environment.GetCommandLineArgs()[0];
            var psi = new ProcessStartInfo
            {
                FileName = exePath,
                Arguments = string.Join(" ", args),
                Verb = "runas",
                UseShellExecute = true
            };
            Process.Start(psi);
            return;
        }
        catch (Exception)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[ERROR] Administrator elevation was declined. WRMS requires Administrator rights to enforce Windows policies.");
            Console.ResetColor();
            return;
        }
    }
}

var builder = Host.CreateApplicationBuilder(args);

// Ensure configuration is always loaded from executable directory
builder.Configuration.SetBasePath(AppContext.BaseDirectory);
builder.Configuration.AddJsonFile("appsettings.json", optional: true, reloadOnChange: true);

// Configure Windows Service integration
// Sets host lifetime to WindowsServiceLifetime and ContentRoot to AppContext.BaseDirectory
builder.Services.AddWindowsService(options =>
{
    options.ServiceName = "WRMS.Agent";
});

// Configure Windows Event Log provider when running on Windows
if (OperatingSystem.IsWindows())
{
    builder.Services.Configure<EventLogSettings>(options =>
    {
        options.SourceName = "WRMS.Agent";
        options.LogName = "Application";
    });
}

// Strongly typed configuration sections
builder.Services.Configure<AgentSettings>(
    builder.Configuration.GetSection(AgentSettings.SectionName));

builder.Services.Configure<PolicySettings>(
    builder.Configuration.GetSection(PolicySettings.SectionName));

builder.Services.Configure<BackendSettings>(
    builder.Configuration.GetSection(BackendSettings.SectionName));

// Security & Validation Services
builder.Services.AddSingleton<IPrivilegeService, PrivilegeService>();
builder.Services.AddSingleton<IPolicyValidationService, PolicyValidationService>();

// Windows OS Abstraction Services
builder.Services.AddSingleton<IWindowsRegistryService, WindowsRegistryService>();
builder.Services.AddSingleton<IHostsFileManager, HostsFileManager>();
builder.Services.AddSingleton<IFirewallInspectorService, FirewallInspectorService>();
builder.Services.AddSingleton<IPortScannerService, PortScannerService>();
builder.Services.AddSingleton<ISoftwareInventoryService, SoftwareInventoryService>();
builder.Services.AddSingleton<IGeoLocationService, GeoLocationService>();
builder.Services.AddSingleton<IForegroundUsageTracker, ForegroundUsageTracker>();
builder.Services.AddSingleton<UserSessionLauncher>();

// Core Domain Services
builder.Services.AddSingleton<IDeviceIdentityService, DeviceIdentityService>();
builder.Services.AddSingleton<IPolicyStateService, PolicyStateService>();

// Policy Enforcement Handlers
builder.Services.AddSingleton<IWebsitePolicyService, WebsitePolicyService>();
builder.Services.AddSingleton<IBrowserPolicyService, BrowserPolicyService>();
builder.Services.AddSingleton<IApplicationPolicyService, ApplicationPolicyService>();
builder.Services.AddSingleton<IUsbPolicyService, UsbPolicyService>();
builder.Services.AddSingleton<IPolicyApplicationService, PolicyApplicationService>();

// Backend REST API Client & HTTP Transport
builder.Services.AddSingleton(sp =>
{
    var backend = builder.Configuration.GetSection(BackendSettings.SectionName).Get<BackendSettings>() ?? new BackendSettings();
    var client = new HttpClient
    {
        Timeout = TimeSpan.FromSeconds(Math.Max(3, backend.RequestTimeoutSeconds))
    };
    if (Uri.TryCreate(backend.ApiBaseUrl, UriKind.Absolute, out var uri))
    {
        client.BaseAddress = uri;
    }
    return client;
});
builder.Services.AddSingleton<IAgentApiClient, AgentApiClient>();

// Policy Providers (ApiPolicyProvider with offline caching and POC fallback)
builder.Services.AddSingleton<IPocPolicyProvider, PocPolicyProvider>();
builder.Services.AddSingleton<IPolicyProvider, ApiPolicyProvider>();

// Background Worker Service
builder.Services.AddHostedService<Worker>();

var host = builder.Build();
await host.RunAsync();
