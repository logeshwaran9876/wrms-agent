namespace WRMS.Agent.Services;

public interface IFirewallInspectorService
{
    (string Status, bool Enabled, bool Domain, bool Private, bool Public) GetFirewallStatus();
}
