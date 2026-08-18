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
    public class AdvancedDfirMilestone3Tests
    {
        [Fact]
        public void RansomwareDetectionEngine_DetectsShadowCopyDeletionAndEncryptedExtensions()
        {
            var engine = new RansomwareDetectionEngine();
            var events = new List<ParsedEvent>
            {
                new ParsedEvent
                {
                    EventId = 4688,
                    TimeCreated = DateTime.UtcNow,
                    MachineName = "FILE-SERVER-01",
                    Message = "A new process was created. Command Line: vssadmin delete shadows /all /quiet"
                },
                new ParsedEvent
                {
                    EventId = 4663,
                    TimeCreated = DateTime.UtcNow.AddMinutes(1),
                    MachineName = "FILE-SERVER-01",
                    Message = "An attempt was made to access an object. Object Name: C:\\Shares\\Finance\\Q4_Report.xlsx.lockbit"
                }
            };

            var findings = engine.AnalyzeEvents(events);

            Assert.NotNull(findings);
            Assert.Equal(2, findings.Count);
            Assert.Contains(findings, f => f.MitreTechniqueId == "T1490"); // Shadow copy deletion
            Assert.Contains(findings, f => f.MitreTechniqueId == "T1486"); // Ransomware encryption
        }

        [Fact]
        public void AutomatedRuleGenerator_SynthesizesValidYaraAndSigmaRules()
        {
            var generator = new AutomatedRuleGenerator();
            var iocs = new List<IocItem>
            {
                new IocItem { Type = IocType.Hash, Value = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
                new IocItem { Type = IocType.Domain, Value = "malicious-c2-server.com" },
                new IocItem { Type = IocType.IPv4, Value = "198.51.100.24" }
            };

            var rules = generator.GenerateRulesFromIocs("INC-2026-0818", iocs);

            Assert.NotNull(rules);
            Assert.Equal(3, rules.TotalIocsIncluded);
            Assert.Contains("rule Incident_INC_2026_0818_ThreatDetection", rules.YARA_Rule);
            Assert.Contains("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", rules.YARA_Rule);
            Assert.Contains("title: Detecție IOC Incident INC_2026_0818", rules.Sigma_YAML_Rule);
            Assert.Contains("malicious-c2-server.com", rules.Sigma_YAML_Rule);
        }

        [Fact]
        public async Task VolatilityBridgeParser_ParsesMalfindJson()
        {
            var parser = new VolatilityBridgeParser();
            string tempJson = Path.Combine(Path.GetTempPath(), "windows.malfind.json");
            try
            {
                string jsonContent = @"[
                    {
                        ""PID"": 1420,
                        ""Process"": ""lsass.exe"",
                        ""Protection"": ""PAGE_EXECUTE_READWRITE"",
                        ""Start VPN"": ""0x7ffb12340000""
                    }
                ]";
                File.WriteAllText(tempJson, jsonContent);

                Assert.True(parser.CanParse(tempJson));

                var results = await parser.ParseAsync(tempJson, "RAM-DUMP-HOST-01");
                Assert.NotNull(results);
                Assert.Single(results);
                Assert.Equal("Injecție Memorie RAM (Volatility malfind)", results[0].ArtifactType);
                Assert.Equal("T1055.012", results[0].MitreTechniqueId);
                Assert.Equal("lsass.exe (PID 1420)", results[0].Name);
            }
            finally
            {
                if (File.Exists(tempJson)) File.Delete(tempJson);
            }
        }

        [Fact]
        public async Task M365EntraIdLogsParser_ParsesCloudSignInTelemetry()
        {
            var parser = new M365EntraIdLogsParser();
            string tempSignIn = Path.Combine(Path.GetTempPath(), "signin_logs_entra.json");
            try
            {
                string jsonContent = @"[
                    {
                        ""userPrincipalName"": ""admin@sec-corp.ro"",
                        ""ipAddress"": ""198.51.100.99"",
                        ""location"": {
                            ""city"": ""Bucharest"",
                            ""countryOrRegion"": ""Romania""
                        },
                        ""status"": {
                            ""errorCode"": 0
                        }
                    }
                ]";
                File.WriteAllText(tempSignIn, jsonContent);

                Assert.True(parser.CanParse(tempSignIn));

                var results = await parser.ParseAsync(tempSignIn, "M365-TENANT");
                Assert.NotNull(results);
                Assert.Single(results);
                Assert.Equal("Entra ID Sign-in Telemetry", results[0].ArtifactType);
                Assert.Equal("T1078.004", results[0].MitreTechniqueId);
                Assert.Equal("Autentificare admin@sec-corp.ro", results[0].Name);
            }
            finally
            {
                if (File.Exists(tempSignIn)) File.Delete(tempSignIn);
            }
        }
    }
}
