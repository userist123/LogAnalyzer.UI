using System;
using System.Collections.Generic;
using LogAnalyzer.Core.Models;
using LogAnalyzer.Core.Services;
using Xunit;

namespace LogAnalyzer.UI.Tests
{
    public class AdAuditAndUbaEngineTests
    {
        [Fact]
        public void StandaloneSamAuditEngine_Detects_LocalAdminTamperingAndUsbStorage()
        {
            var engine = new StandaloneSamAuditEngine();
            var events = new List<ParsedEvent>
            {
                new ParsedEvent { EventId = 4732, Message = "Member added to BUILTIN\\Administrators", TimeCreated = DateTime.UtcNow },
                new ParsedEvent { EventId = 4719, Message = "System audit policy was changed", TimeCreated = DateTime.UtcNow },
                new ParsedEvent { EventId = 20001, Message = "USBSTOR\\Disk&Ven_SanDisk", TimeCreated = DateTime.UtcNow },
                new ParsedEvent { EventId = 4672, Message = "Special privileges assigned: SeDebugPrivilege", TimeCreated = DateTime.UtcNow }
            };

            var summary = engine.GetSummary(events);
            var findings = engine.Analyze(events);

            Assert.Equal(1, summary.LocalAdminGroupModifications);
            Assert.Equal(1, summary.AuditPolicyTamperingCount);
            Assert.Equal(1, summary.UsbStorageEventsCount);
            Assert.Equal(1, summary.HighPrivilegeAssignmentsCount);

            Assert.Equal(4, findings.Count);
            Assert.Contains(findings, f => f.FindingType.Contains("Administrators"));
            Assert.Contains(findings, f => f.FindingType.Contains("Auditare"));
            Assert.Contains(findings, f => f.FindingType.Contains("USB"));
            Assert.Contains(findings, f => f.FindingType.Contains("SeDebugPrivilege"));
        }

        [Fact]
        public void DnsAuditEngine_Detects_DnsRecordAndZoneTampering()
        {
            var engine = new DnsAuditEngine();
            var events = new List<ParsedEvent>
            {
                new ParsedEvent { EventId = 258, Message = "DNS Server resource record modified", TimeCreated = DateTime.UtcNow },
                new ParsedEvent { EventId = 259, Message = "DNS Server resource record deleted", TimeCreated = DateTime.UtcNow }
            };

            var findings = engine.Analyze(events);

            Assert.Equal(2, findings.Count);
            Assert.Contains(findings, f => f.FindingType.Contains("Creare / Modificare"));
            Assert.Contains(findings, f => f.FindingType.Contains("Ștergere Înregistrare"));
        }

        [Fact]
        public void ComplianceAuditEngine_Evaluates_Hg585AndNis2()
        {
            var engine = new ComplianceAuditEngine();
            var adSummary = new AdAuditSummary { KerberosAttacksDetected = 1 };
            var samSummary = new StandaloneSamSummary { UsbStorageEventsCount = 1 };

            var results = engine.Evaluate(new List<ParsedEvent>(), adSummary, samSummary, 0, 1);

            Assert.NotEmpty(results);
            Assert.Contains(results, r => r.Framework.Contains("HG 585/2002") && r.Status == "NON-CONFORM");
            Assert.Contains(results, r => r.Framework.Contains("NIS2") && r.Status == "NON-CONFORM");
            Assert.Contains(results, r => r.Framework.Contains("ISO/IEC 27042") && r.Status == "CONFORM");
        }

        [Fact]
        public void UserBehaviorAnalyticsEngine_Detects_OffHoursAndBruteForceSuccess()
        {
            var engine = new UserBehaviorAnalyticsEngine();
            var events = new List<ParsedEvent>
            {
                // Failed logons followed by success
                new ParsedEvent { EventId = 4625, Message = "TargetUserName: victim_admin", TimeCreated = DateTime.UtcNow.Date.AddHours(2).AddMinutes(1), MachineName = "DC01" },
                new ParsedEvent { EventId = 4625, Message = "TargetUserName: victim_admin", TimeCreated = DateTime.UtcNow.Date.AddHours(2).AddMinutes(2), MachineName = "DC01" },
                new ParsedEvent { EventId = 4625, Message = "TargetUserName: victim_admin", TimeCreated = DateTime.UtcNow.Date.AddHours(2).AddMinutes(3), MachineName = "DC01" },
                new ParsedEvent { EventId = 4624, Message = "TargetUserName: victim_admin", TimeCreated = DateTime.UtcNow.Date.AddHours(2).AddMinutes(4), MachineName = "DC01" }
            };

            var anomalies = engine.Evaluate(events);

            Assert.NotEmpty(anomalies);
            Assert.Contains(anomalies, a => a.AnomalyType.Contains("Brute-Force Compromise"));
            Assert.Contains(anomalies, a => a.AnomalyType.Contains("Orelor Normale"));
        }

        [Fact]
        public void AdAuditReportService_Generates_ValidCsvOutput()
        {
            var service = new AdAuditReportService();
            var summary = new AdAuditSummary
            {
                TotalAdEventsAnalyzed = 150,
                UserAccountsCreated = 3,
                AccountLockouts = 5,
                PrivilegedGroupChanges = 2,
                KerberosAttacksDetected = 1
            };

            var findings = new List<KerberosAdFinding>
            {
                new KerberosAdFinding
                {
                    AttackType = "Kerberoasting",
                    Category = "Active Directory Security",
                    Severity = "Critical",
                    TargetAccount = "svc_sql",
                    MitreTechniqueId = "T1558.003",
                    Description = "RC4 encryption requested for SPN"
                }
            };

            var uba = new List<UbaAnomalyItem>
            {
                new UbaAnomalyItem
                {
                    Username = "svc_backup",
                    AnomalyType = "Off-Hours Logon",
                    Severity = "High",
                    RiskWeight = 85.0
                }
            };

            var csv = service.GenerateCsvReport(summary, findings, uba);

            Assert.NotNull(csv);
            Assert.Contains("ADAUDIT PLUS SUITE", csv);
            Assert.Contains("Kerberoasting", csv);
            Assert.Contains("svc_sql", csv);
            Assert.Contains("svc_backup", csv);
        }
    }
}
