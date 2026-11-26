namespace WRMS.Agent.Services;

using WRMS.Agent.Models;

public interface IPortScannerService
{
    List<OpenPortInfo> GetActiveListeningPorts();
}
