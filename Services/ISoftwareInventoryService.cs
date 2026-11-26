namespace WRMS.Agent.Services;

using WRMS.Agent.Models;

public interface ISoftwareInventoryService
{
    List<InstalledSoftwareInfo> GetInstalledSoftware();
    void RefreshExecutionCounts(List<InstalledSoftwareInfo> softwareList, DailyAppUsageSummary? dailyUsage = null);
}
