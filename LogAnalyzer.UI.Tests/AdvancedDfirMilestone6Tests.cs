using System;
using System.Collections.Generic;
using System.IO;
using LogAnalyzer.Core.Models;
using LogAnalyzer.Core.Services;
using Xunit;

namespace LogAnalyzer.UI.Tests
{
    public class AdvancedDfirMilestone6Tests
    {
        [Fact]
        public void ProcessInjectionDetector_DetectsHollowingAndEarlyBird()
        {
            var detector = new ProcessInjectionDetector();
            var events = new List<ParsedEvent>
            {
                new ParsedEvent
                {
                    EventId = 4688,
                    TimeCreated = DateTime.UtcNow,
                    MachineName = "SRV-WORKSTATION-01",
                    Message = "Process Create: svchost.exe (CREATE_SUSPENDED, process_hollowing target)"
                },
                new ParsedEvent
                {
                    EventId = 8,
                    TimeCreated = DateTime.UtcNow.AddMinutes(1),
                    MachineName = "SRV-WORKSTATION-01",
                    Message = "CreateRemoteThread: QueueUserAPC earlybird shellcode injection"
                }
            };

            var findings = detector.DetectInjections(events);

            Assert.NotNull(findings);
            Assert.Equal(2, findings.Count);
            Assert.Contains(findings, f => f.MitreTechniqueId == "T1055.012"); // Hollowing
            Assert.Contains(findings, f => f.MitreTechniqueId == "T1055.004"); // Early Bird APC
        }

        [Fact]
        public void DnsTunnelingClassifier_DetectsTunnelingAndDga()
        {
            var classifier = new DnsTunnelingClassifier();
            var queries = new List<string>
            {
                "a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6.tunnel.exfil-c2.net",
                "xzkptqwmnbvcdrfg.biz",
                "google.com"
            };

            var results = classifier.AnalyzeDnsQueries(queries);

            Assert.NotNull(results);
            Assert.Equal(2, results.Count);
            Assert.Contains(results, r => r.IsTunnelingCandidate);
            Assert.Contains(results, r => r.IsDgaCandidate);
            Assert.DoesNotContain(results, r => r.QueryDomain == "google.com");
        }

        [Fact]
        public void OfflineThreatFeedMatcher_MatchesHashesAndIpsOffline()
        {
            var matcher = new OfflineThreatFeedMatcher();
            var hashes = new[] { "44d88612fea8a8f36de82e1278abb02f", "clean_file_hash_123" };
            var ips = new[] { "185.220.101.5", "192.168.1.1" };
            var domains = new[] { "malicious-c2-server.com", "microsoft.com" };

            var matches = matcher.MatchAllIocs(hashes, ips, domains);

            Assert.NotNull(matches);
            Assert.Equal(3, matches.Count);
            Assert.Contains(matches, m => m.MalwareFamily == "WannaCry");
            Assert.Contains(matches, m => m.ThreatActorOrCampaign == "Tor Exit Node");
            Assert.Contains(matches, m => m.ThreatActorOrCampaign == "APT29 C2 Infrastructure");
        }

        [Fact]
        public void CaseSnapshotService_ExportsAndLoadsInvestigationPackage()
        {
            var service = new CaseSnapshotService();
            string tempDfir = Path.Combine(Path.GetTempPath(), $"Investigation_{Guid.NewGuid():N}.dfir");

            try
            {
                var pkg = new CaseSnapshotPackage
                {
                    Manifest = new CaseSnapshotManifest
                    {
                        CaseId = "INC-2026-DFIR-001",
                        CaseTitle = "Investigație Atac Ransomware",
                        LeadAnalyst = "Investigator SOC Principal"
                    },
                    SessionNotes = "Analiză inițială finalizată. Izolare host realizată cu succes.",
                    Issues = new List<DetectedIssue>
                    {
                        new DetectedIssue
                        {
                            Title = "Detecție Shadow Copy Deletion",
                            Severity = "Critical",
                            Explanation = "vssadmin delete shadows rulat de atacator",
                            MitreTechniqueId = "T1490"
                        }
                    },
                    Iocs = new List<IocItem>
                    {
                        new IocItem { Type = IocType.IPv4, Value = "198.51.100.24" }
                    }
                };

                service.ExportCaseSnapshot(tempDfir, pkg);
                Assert.True(File.Exists(tempDfir));

                var loaded = service.LoadCaseSnapshot(tempDfir);
                Assert.NotNull(loaded);
                Assert.Equal("INC-2026-DFIR-001", loaded.Manifest.CaseId);
                Assert.Single(loaded.Issues);
                Assert.Equal("Detecție Shadow Copy Deletion", loaded.Issues[0].Title);
                Assert.Single(loaded.Iocs);
                Assert.Equal("198.51.100.24", loaded.Iocs[0].Value);
            }
            finally
            {
                if (File.Exists(tempDfir)) File.Delete(tempDfir);
            }
        }
    }
}
