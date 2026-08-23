using System;

namespace LogAnalyzer.Core.Models
{
    /// <summary>
    /// Anomalie comportamentală detectată de motorul UBA.
    /// </summary>
    public class UbaAnomalyItem
    {
        public string Username { get; set; } = string.Empty;
        public string Workstation { get; set; } = "Workstation";
        public string AnomalyType { get; set; } = string.Empty;
        public string Severity { get; set; } = "Medium";
        public string Description { get; set; } = string.Empty;
        public double RiskWeight { get; set; } = 50.0;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Activitate sesiune utilizator (timp activ, blocări, deblocări ecran).
    /// </summary>
    public class EmployeeSessionActivity
    {
        public string Username { get; set; } = string.Empty;
        public string Workstation { get; set; } = string.Empty;
        public DateTime LogonTime { get; set; } = DateTime.UtcNow;
        public DateTime? LogoffTime { get; set; }
        public double ActiveHours { get; set; }
        public int LockCount { get; set; }
        public int UnlockCount { get; set; }
        public string SessionStatus { get; set; } = "Active";
    }
}
