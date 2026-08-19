using System;
using System.Collections.Generic;
using LogAnalyzer.Core.Models;
using LogAnalyzer.Core.Services.Network;
using Xunit;

namespace LogAnalyzer.UI.Tests
{
    public class LiveMonitoringSecurityTests
    {
        [Fact]
        public void EvaluateLiveEvent_DetectsRansomwareShadowCopyDeletion()
        {
            var engine = new LiveSecurityMonitoringEngine();
            var ev = new ParsedEvent
            {
                EventId = 4688,
                MachineName = "SRV-FINANCE-01",
                Message = "Process CommandLine: vssadmin.exe delete shadows /all /quiet",
                TimeCreated = DateTime.UtcNow
            };

            var alert = engine.EvaluateLiveEvent(ev);

            Assert.NotNull(alert);
            Assert.Equal("Critical", alert.Severity);
            Assert.Equal("T1490", alert.MitreTechniqueId);
            Assert.Contains("Ransomware", alert.Title);
        }

        [Fact]
        public void EvaluateLiveEvent_DetectsEncodedPowerShellExecution()
        {
            var engine = new LiveSecurityMonitoringEngine();
            var ev = new ParsedEvent
            {
                EventId = 4104,
                MachineName = "WS-DEVELOPER-02",
                Message = "Creating Scriptblock text: powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA... -bypass -nop -w hidden",
                TimeCreated = DateTime.UtcNow
            };

            var alert = engine.EvaluateLiveEvent(ev);

            Assert.NotNull(alert);
            Assert.Equal("High", alert.Severity);
            Assert.Equal("T1059.001", alert.MitreTechniqueId);
            Assert.Contains("PowerShell", alert.Title);
        }

        [Fact]
        public void EvaluateLiveEvent_DetectsLsassMemoryDump()
        {
            var engine = new LiveSecurityMonitoringEngine();
            var ev = new ParsedEvent
            {
                EventId = 10,
                MachineName = "DC-PRIMARY",
                Message = "SourceImage: C:\\Temp\\mimikatz.exe, TargetImage: C:\\Windows\\System32\\lsass.exe, GrantedAccess: 0x1010",
                TimeCreated = DateTime.UtcNow
            };

            var alert = engine.EvaluateLiveEvent(ev);

            Assert.NotNull(alert);
            Assert.Equal("Critical", alert.Severity);
            Assert.Equal("T1003.001", alert.MitreTechniqueId);
            Assert.Contains("LSASS", alert.Title);
        }

        [Fact]
        public void EvaluateLiveEvent_ReturnsNullForBenignEvents()
        {
            var engine = new LiveSecurityMonitoringEngine();
            var ev = new ParsedEvent
            {
                EventId = 4624,
                MachineName = "WS-ACCOUNTING",
                Message = "User SYSTEM successfully logged on (LogonType: 5 - Service)",
                TimeCreated = DateTime.UtcNow
            };

            var alert = engine.EvaluateLiveEvent(ev);

            Assert.Null(alert);
        }
    }
}
