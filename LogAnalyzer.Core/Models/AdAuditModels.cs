using System;
using System.Collections.Generic;

namespace LogAnalyzer.Core.Models
{
    /// <summary>
    /// Sumar metrici executive pentru activitatea Active Directory (ADAudit Plus Suite).
    /// </summary>
    public class AdAuditSummary
    {
        public int TotalAdEventsAnalyzed { get; set; }
        public int UserAccountsCreated { get; set; }
        public int UserAccountsModified { get; set; }
        public int UserAccountsDeleted { get; set; }
        public int PasswordResets { get; set; }
        public int AccountLockouts { get; set; }
        public int PrivilegedGroupChanges { get; set; }
        public int GpoPolicyChanges { get; set; }
        public int KerberosAttacksDetected { get; set; }
    }

    /// <summary>
    /// Detecție atac sau activitate malițioasă pe Active Directory & Kerberos.
    /// </summary>
    public class KerberosAdFinding
    {
        public string Category { get; set; } = string.Empty;
        public string AttackType { get; set; } = string.Empty;
        public string TargetAccount { get; set; } = string.Empty;
        public string ClientIp { get; set; } = string.Empty;
        public string Severity { get; set; } = "High";
        public string MitreTechniqueId { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string ContainmentActionRo { get; set; } = "Izolare cont și rotație imediată a parolei / SPN.";
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public DateTime DetectedAt => Timestamp;
    }

    /// <summary>
    /// Eveniment granular de modificare atribut obiect Active Directory (Before / After Delta).
    /// </summary>
    public class AdAttributeDelta
    {
        public string ObjectClass { get; set; } = "User";
        public string ObjectDn { get; set; } = string.Empty;
        public string AttributeName { get; set; } = string.Empty;
        public string OldValue { get; set; } = "-";
        public string NewValue { get; set; } = "-";
        public string Operation { get; set; } = "Value Added";
        public string ModifiedBy { get; set; } = "SYSTEM";
        public string SecurityImpact { get; set; } = "Low";
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Detecție securitate identitate hibridă Azure AD / Entra ID Cloud.
    /// </summary>
    public class AzureAdFinding
    {
        public string ActivityType { get; set; } = string.Empty;
        public string UserPrincipalName { get; set; } = string.Empty;
        public string Severity { get; set; } = "High";
        public string SourceLocationOrIp { get; set; } = string.Empty;
        public string MitreTechniqueId { get; set; } = "T1078.004";
        public string Description { get; set; } = string.Empty;
        public string RemediationActionRo { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Detecție activitate fișiere pe servere Windows și stocare NAS.
    /// </summary>
    public class FileServerAuditFinding
    {
        public string ActivityType { get; set; } = string.Empty;
        public string SharePathOrFileName { get; set; } = string.Empty;
        public string AccessedBy { get; set; } = string.Empty;
        public string Severity { get; set; } = "High";
        public string ServerHost { get; set; } = "FileServer01";
        public string MitreTechniqueId { get; set; } = "T1486";
        public string Description { get; set; } = string.Empty;
        public string RemediationActionRo { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Detecție modificare înregistrare sau zonă server DNS.
    /// </summary>
    public class DnsAuditFinding
    {
        public string FindingType { get; set; } = string.Empty;
        public string RecordName { get; set; } = string.Empty;
        public string ZoneName { get; set; } = string.Empty;
        public string Severity { get; set; } = "Medium";
        public string MitreTechniqueId { get; set; } = "T1071.004";
        public string Description { get; set; } = string.Empty;
        public string RemediationActionRo { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Script de restaurare/rollback PowerShell generat automat pentru incidente AD.
    /// </summary>
    public class AdRollbackScript
    {
        public string TargetObject { get; set; } = string.Empty;
        public string ActionDescription { get; set; } = string.Empty;
        public string GeneratedPowerShellScript { get; set; } = string.Empty;
        public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
    }
}
