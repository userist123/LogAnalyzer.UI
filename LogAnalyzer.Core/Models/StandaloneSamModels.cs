using System;

namespace LogAnalyzer.Core.Models
{
    /// <summary>
    /// Sumar metrici securitate bază SAM și stație standalone.
    /// </summary>
    public class StandaloneSamSummary
    {
        public int LocalAccountsCreated { get; set; }
        public int LocalAccountsDeleted { get; set; }
        public int LocalAdminGroupModifications { get; set; }
        public int AuditPolicyTamperingCount { get; set; }
        public int UsbStorageEventsCount { get; set; }
        public int HighPrivilegeAssignmentsCount { get; set; }
    }

    /// <summary>
    /// Detecție forensică pe o stație izolată / standalone fără domeniu.
    /// </summary>
    public class StandaloneSamFinding
    {
        public string FindingType { get; set; } = string.Empty;
        public string Category { get; set; } = "Local Endpoint Security";
        public string Severity { get; set; } = "Medium";
        public string TargetAccountOrResource { get; set; } = string.Empty;
        public string MitreTechniqueId { get; set; } = "T1078.003";
        public string SourceProcessOrDevice { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string RemediationActionRo { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }
}
