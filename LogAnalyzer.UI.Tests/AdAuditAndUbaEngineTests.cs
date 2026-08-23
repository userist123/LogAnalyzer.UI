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
        public void AiCopilotInvestigationEngine_Generates_StructuredReportAndContainment()
        {
            var engine = new AiCopilotInvestigationEngine();
            var res = engine.InvestigateFinding("Kerberoasting", "Kerberos", "svc_sql", "RC4 ticket requested", "T1558.003");

            Assert.NotNull(res);
            Assert.Equal("Critic", res.RiskLevel);
            Assert.Contains("T1558.003", res.MitreKillChainMapping);
            Assert.NotEmpty(res.RecommendedContainmentSteps);
            Assert.Contains("HG 585/2002", res.RegulatoryImpactRo);
        }

        [Fact]
        public void ProcessLineageCorrelator_Builds_ParentChildTree()
        {
            var engine = new ProcessLineageCorrelator();
            var events = new List<ParsedEvent>
            {
                new ParsedEvent { EventId = 1, Message = "Image: C:\\Windows\\System32\\cmd.exe\nProcessId: 0x100\nParentProcessId: 0x0\nCommandLine: cmd.exe", TimeCreated = DateTime.UtcNow },
                new ParsedEvent { EventId = 1, Message = "Image: C:\\Windows\\System32\\powershell.exe\nProcessId: 0x200\nParentProcessId: 0x100\nCommandLine: powershell.exe -enc AAAA", TimeCreated = DateTime.UtcNow.AddSeconds(1) }
            };

            var roots = engine.BuildLineageTrees(events);

            Assert.Single(roots);
            Assert.Equal("cmd.exe", roots[0].ProcessName);
            Assert.Single(roots[0].Children);
            Assert.Equal("powershell.exe", roots[0].Children[0].ProcessName);
            Assert.True(roots[0].Children[0].IsSuspicious);
        }

        [Fact]
        public void EmployeeActivityAuditEngine_Calculates_WorkHoursAndLockStates()
        {
            var engine = new EmployeeActivityAuditEngine();
            var events = new List<ParsedEvent>
            {
                new ParsedEvent { EventId = 4624, Message = "TargetUserName: analyst_john", MachineName = "WS01", TimeCreated = DateTime.UtcNow.Date.AddHours(8) },
                new ParsedEvent { EventId = 4800, Message = "TargetUserName: analyst_john", MachineName = "WS01", TimeCreated = DateTime.UtcNow.Date.AddHours(12) },
                new ParsedEvent { EventId = 4801, Message = "TargetUserName: analyst_john", MachineName = "WS01", TimeCreated = DateTime.UtcNow.Date.AddHours(13) },
                new ParsedEvent { EventId = 4634, Message = "TargetUserName: analyst_john", MachineName = "WS01", TimeCreated = DateTime.UtcNow.Date.AddHours(17) }
            };

            var activities = engine.AnalyzeWorkHours(events);

            Assert.Single(activities);
            var a = activities[0];
            Assert.Equal("analyst_john", a.Username);
            Assert.Equal(1, a.LockCount);
            Assert.Equal(1, a.UnlockCount);
            Assert.Equal("Closed", a.SessionStatus);
            Assert.True(a.ActiveHours > 0);
        }

        [Fact]
        public void FileStorageAnalyticsEngine_Detects_OpenAclAndOrphanedSid()
        {
            var engine = new FileStorageAnalyticsEngine();
            var events = new List<ParsedEvent>
            {
                new ParsedEvent { EventId = 5145, Message = "Access mask 0x1F01FF Everyone granted Full Control", TimeCreated = DateTime.UtcNow },
                new ParsedEvent { EventId = 4663, Message = "Account Deleted Account SID S-1-5-21-999-999", TimeCreated = DateTime.UtcNow }
            };

            var items = engine.AnalyzeStorageRisks(events);

            Assert.Equal(2, items.Count);
            Assert.Contains(items, i => i.RiskCategory.Contains("Everyone"));
            Assert.Contains(items, i => i.RiskCategory.Contains("Orphaned SID"));
        }

        [Fact]
        public void AdAuditHtmlReportService_Generates_ValidHtmlWithStyles()
        {
            var service = new AdAuditHtmlReportService();
            var adSummary = new AdAuditSummary { TotalAdEventsAnalyzed = 500, KerberosAttacksDetected = 2 };
            var samSummary = new StandaloneSamSummary { LocalAdminGroupModifications = 1 };

            var html = service.GenerateHtmlReport(adSummary, samSummary, new List<KerberosAdFinding>(), new List<StandaloneSamFinding>(), new List<UbaAnomalyItem>(), new List<ComplianceCheckResult>());

            Assert.NotNull(html);
            Assert.Contains("<!DOCTYPE html>", html);
            Assert.Contains("ADAUDIT PLUS", html);
            Assert.Contains("500", html);
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
        public void AdAttributeDeltaEngine_Extracts_AttributeModifications()
        {
            var engine = new AdAttributeDeltaEngine();
            var events = new List<ParsedEvent>
            {
                new ParsedEvent { EventId = 5136, Message = "Object DN: CN=AdminSDHolder,CN=System,DC=lab,DC=local\nAttribute LDAP Display Name: adminCount\nAttribute Value: 1\nOperation Type: Value Added\nAccount Name: attacker_admin", TimeCreated = DateTime.UtcNow },
                new ParsedEvent { EventId = 4738, Message = "Target Account Name: svc_backup\nSubject: Account Name: admin\nDon't Require Preauth", TimeCreated = DateTime.UtcNow }
            };

            var deltas = engine.ExtractDeltas(events);

            Assert.Equal(2, deltas.Count);
            Assert.Contains(deltas, d => d.AttributeName.Contains("adminCount"));
            Assert.Contains(deltas, d => d.AttributeName.Contains("DONT_REQ_PREAUTH"));
        }

        [Fact]
        public void AzureAdAuditEngine_Detects_GlobalAdminAndRiskySignIns()
        {
            var engine = new AzureAdAuditEngine();
            var events = new List<ParsedEvent>
            {
                new ParsedEvent { EventId = 50126, ProviderName = "Microsoft-Windows-AzureAD-Authentication", Message = "Global Administrator role activated for user", TimeCreated = DateTime.UtcNow },
                new ParsedEvent { EventId = 50126, ProviderName = "Microsoft-Windows-AzureAD-Authentication", Message = "Risky Sign-in / Impossible Travel detected", TimeCreated = DateTime.UtcNow }
            };

            var findings = engine.Analyze(events);

            Assert.Equal(2, findings.Count);
            Assert.Contains(findings, f => f.ActivityType.Contains("Global Administrator"));
            Assert.Contains(findings, f => f.ActivityType.Contains("Impossible Travel"));
        }

        [Fact]
        public void FileServerAuditEngine_Detects_RansomwareAndSensitiveDirectoryAccess()
        {
            var engine = new FileServerAuditEngine();
            var events = new List<ParsedEvent>();
            for (int i = 0; i < 6; i++)
            {
                events.Add(new ParsedEvent { EventId = 4663, Message = $"Object Name: \\Device\\HarddiskVolume2\\Data\\document_{i}.locked with WriteData", TimeCreated = DateTime.UtcNow });
            }
            events.Add(new ParsedEvent { EventId = 4663, Message = "Object Name: \\Device\\HarddiskVolume2\\Confidential\\salarii.xlsx", TimeCreated = DateTime.UtcNow });

            var findings = engine.Analyze(events);

            Assert.Equal(2, findings.Count);
            Assert.Contains(findings, f => f.ActivityType.Contains("Ransomware"));
            Assert.Contains(findings, f => f.ActivityType.Contains("Confidențiale"));
        }

        [Fact]
        public void AdSnapshotRollbackEngine_Generates_PowerShellScript()
        {
            var engine = new AdSnapshotRollbackEngine();
            var script = engine.GenerateRollbackForFinding("Domain Admins Member Escalation", "Domain Admins");

            Assert.NotNull(script);
            Assert.Contains("Remove-ADGroupMember", script.GeneratedPowerShellScript);
            Assert.Contains("Domain Admins", script.GeneratedPowerShellScript);
        }
    }
}
