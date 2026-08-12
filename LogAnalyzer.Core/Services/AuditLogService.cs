using System;
using System.IO;

namespace LogAnalyzer.Core.Services
{
    public class AuditLogService
    {
        private readonly string _logFile;
        private static readonly object _lock = new object();

        public AuditLogService()
        {
            string auditDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "AuditLogs");
            if (!Directory.Exists(auditDir)) Directory.CreateDirectory(auditDir);
            
            _logFile = Path.Combine(auditDir, $"SOC_Audit_{DateTime.Now:yyyyMMdd}.log");
        }

        public void LogAction(string actionType, string details)
        {
            lock (_lock)
            {
                string logEntry = $"[{DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC}] [{actionType}] {details}{Environment.NewLine}";
                File.AppendAllText(_logFile, logEntry);
            }
        }
    }
}