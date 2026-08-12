using System;
using System.Threading.Tasks;

namespace LogAnalyzer.Core.Interfaces
{
    public interface IAuditCollectionService
    {
        Task RunCollectionAsync(string targetType, string outputDir, string hostname, Action<string> logCallback);
        
        void StartSyslogListener(int port, string outputDir, string hostname, Action<string> logCallback);
        void StopSyslogListener();
        bool IsSyslogListenerActive { get; }
    }
}
