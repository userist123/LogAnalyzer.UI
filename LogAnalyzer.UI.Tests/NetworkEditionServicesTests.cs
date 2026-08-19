using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using LogAnalyzer.Core.Models;
using LogAnalyzer.Core.Services.Network;
using Xunit;

namespace LogAnalyzer.UI.Tests
{
    public class NetworkEditionServicesTests
    {
        [Fact]
        public void RemoteTriageService_GeneratesValidWinRmScript()
        {
            var service = new RemoteTriageService();
            var target = new RemoteEndpointTarget
            {
                HostnameOrIp = "WS-FINANCE-04",
                AdminUsername = "corp\\admin_sec",
                UseSsl = true
            };

            string script = service.GenerateWinRmCollectionScript(target, "\\\\SEC-SERVER\\ForensicsShare");

            Assert.NotNull(script);
            Assert.Contains("WS-FINANCE-04", script);
            Assert.Contains("Invoke-Command", script);
            Assert.Contains("wevtutil epl Security", script);
            Assert.Contains("\\\\SEC-SERVER\\ForensicsShare", script);
        }

        [Fact]
        public void SiemForwarderService_FormatsCefSyslogCorrectly()
        {
            var forwarder = new SiemForwarderService();
            var issues = new List<DetectedIssue>
            {
                new DetectedIssue
                {
                    Title = "Tentativă Mimikatz LSASS Dump",
                    Severity = "Critical",
                    MitreTechniqueId = "T1003.001",
                    Explanation = "Acces neautorizat la procesul LSASS de la un proces extern nesemnat."
                }
            };

            var cefList = forwarder.FormatToCefSyslog(issues);

            Assert.NotNull(cefList);
            Assert.Single(cefList);
            Assert.Contains("CEF:0|LogAnalyzer|DFIR Enterprise", cefList[0]);
            Assert.Contains("ALERT_T1003.001", cefList[0]);
            Assert.Contains("Tentativă Mimikatz LSASS Dump", cefList[0]);
        }

        [Fact]
        public async Task LiveThreatIntelService_HandlesEmptyApiKeyGracefully()
        {
            var service = new LiveThreatIntelService();
            var rep = await service.CheckIpReputationAsync("198.51.100.24", "");

            Assert.NotNull(rep);
            Assert.Equal("198.51.100.24", rep.IocValue);
            Assert.Equal(0, rep.MaliciousScore);
            Assert.Contains("Cheia API nu este configurată", rep.Details);
        }
    }
}
