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
