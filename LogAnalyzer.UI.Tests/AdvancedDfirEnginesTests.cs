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
    public class AdvancedDfirEnginesTests
    {
        [Fact]
        public void C2BeaconingDetector_IdentifiesStrictPeriodicTraffic()
        {
            var detector = new C2BeaconingDetector();
            var events = new List<(string Destination, DateTime Timestamp)>();

            // Simulăm 10 conexiuni la fiecare 60 de secunde (jitter minim, CV < 0.05)
            DateTime baseTime = DateTime.UtcNow.AddMinutes(-30);
            for (int i = 0; i < 10; i++)
            {
                events.Add(("185.220.101.5", baseTime.AddSeconds(i * 60)));
            }

            var candidates = detector.AnalyzeConnections(events);

            Assert.NotNull(candidates);
            Assert.NotEmpty(candidates);
            Assert.Equal("185.220.101.5", candidates[0].Destination);
            Assert.Equal("Critical", candidates[0].ThreatLevel);
            Assert.True(candidates[0].CoefficientOfVariation < 0.05);
        }

        [Fact]
        public void SigmaTranspilerService_GeneratesSplunkAndSentinelQueries()
        {
            var transpiler = new SigmaTranspilerService();
            var result = transpiler.Transpile(
                "Detect Mimikatz Execution",
                eventId: "4688",
                imageCondition: "mimikatz.exe",
                commandLineContains: "sekurlsa::logonpasswords");

            Assert.NotNull(result);
            Assert.Contains("index=security", result.SplunkSpl);
            Assert.Contains("EventCode=4688", result.SplunkSpl);
            Assert.Contains("sekurlsa::logonpasswords", result.SplunkSpl);

            Assert.Contains("SecurityEvent", result.SentinelKql);
            Assert.Contains("where EventID == 4688", result.SentinelKql);

            Assert.Contains("Get-WinEvent", result.PowerShellHunting);
            Assert.Contains("4688", result.PowerShellHunting);
        }

        [Fact]
        public void LateralMovementEngine_BuildsGraphFromRdpAndPsExecEvents()
        {
            var engine = new LateralMovementEngine();
            var events = new List<ParsedEvent>
            {
                new ParsedEvent
                {
                    EventId = 4624,
                    TimeCreated = DateTime.UtcNow,
                    MachineName = "FILE-SERVER-01",
                    Message = "An account was successfully logged on. Logon Type:\t\t10\nAccount Name:\t\tAdminUser\nSource Network Address:\t192.168.1.150"
                },
                new ParsedEvent
                {
                    EventId = 7045,
                    TimeCreated = DateTime.UtcNow.AddMinutes(2),
                    MachineName = "DB-SERVER-02",
                    Message = "A service was installed in the system. Service Name: PSEXESVC"
                }
            };

            var graph = engine.BuildGraph(events);

            Assert.NotNull(graph);
            Assert.True(graph.TotalPivots >= 2);
            Assert.Contains(graph.Nodes, n => n == "FILE-SERVER-01");
            Assert.Contains(graph.Nodes, n => n == "192.168.1.150");
            Assert.Contains(graph.Edges, e => e.Protocol.Contains("RDP"));
            Assert.Contains(graph.Edges, e => e.Protocol.Contains("PsExec"));
        }

        [Fact]
        public async Task UserActivityParser_ParsesLnkShortcut()
        {
            var parser = new UserActivityParser();
            string tempLnk = Path.Combine(Path.GetTempPath(), $"test_shortcut_{Guid.NewGuid():N}.lnk");
            try
            {
                byte[] lnkBytes = new byte[100];
                lnkBytes[0] = 0x4C; // Header Size 76 bytes
                // Scriem o cale ASCII simplă în LNK
                byte[] pathBytes = System.Text.Encoding.ASCII.GetBytes("C:\\Confidential\\passwords.xlsx");
                Buffer.BlockCopy(pathBytes, 0, lnkBytes, 76, Math.Min(pathBytes.Length, 24));

                File.WriteAllBytes(tempLnk, lnkBytes);

                Assert.True(parser.CanParse(tempLnk));

                var results = await parser.ParseAsync(tempLnk, "CEO-LAPTOP");
                Assert.NotNull(results);
                Assert.NotEmpty(results);
                Assert.Equal("LNK Shortcut Activity", results[0].ArtifactType);
                Assert.Equal("CEO-LAPTOP", results[0].HostId);
            }
            finally
            {
                if (File.Exists(tempLnk)) File.Delete(tempLnk);
            }
        }
    }
}
