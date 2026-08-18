using System;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using LogAnalyzer.Core.Models;
using LogAnalyzer.Core.Services;
using LogAnalyzer.Infrastructure.Parsers;
using Xunit;

namespace LogAnalyzer.UI.Tests
{
    public class AdvancedDfirMilestone4Tests
    {
        [Fact]
        public void SysmonCorrelationEngine_DetectsMasqueradingAndLsassAccess()
        {
            var engine = new SysmonCorrelationEngine();
            var events = new List<ParsedEvent>
            {
                new ParsedEvent
                {
                    EventId = 1,
                    TimeCreated = DateTime.UtcNow,
                    Message = "Process Create: Image: C:\\Windows\\svchost.exe, OriginalFileName: cmd.exe, CommandLine: svchost.exe /c whoami"
                },
                new ParsedEvent
                {
                    EventId = 10,
                    TimeCreated = DateTime.UtcNow.AddMinutes(1),
                    Message = "Process accessed: TargetImage: C:\\Windows\\System32\\lsass.exe, GrantedAccess: 0x1010, SourceImage: C:\\Temp\\mimikatz.exe"
                }
            };

            var findings = engine.AnalyzeSysmonEvents(events);

            Assert.NotNull(findings);
            Assert.Equal(2, findings.Count);
            Assert.Contains(findings, f => f.MitreTechniqueId == "T1036.003"); // Masquerading
            Assert.Contains(findings, f => f.MitreTechniqueId == "T1003.001"); // LSASS Access
        }

        [Fact]
        public void StixBundleExportService_GeneratesValidStix21JsonBundle()
        {
            var exporter = new StixBundleExportService();
            var iocs = new List<IocItem>
            {
                new IocItem { Type = IocType.Hash, Value = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
                new IocItem { Type = IocType.IPv4, Value = "198.51.100.24" }
            };

            var issues = new List<DetectedIssue>
            {
                new DetectedIssue
                {
                    Title = "Extragere Credențiale LSASS (Mimikatz)",
                    MitreTechniqueId = "T1003.001",
                    Explanation = "Acces neautorizat la memoria procesului LSASS"
                }
            };

            string json = exporter.ExportToStix21Json("INC-001", "APT29 (Cozy Bear)", iocs, issues);

            Assert.NotNull(json);
            Assert.Contains("\"type\": \"bundle\"", json);
            Assert.Contains("\"spec_version\": \"2.1\"", json);
            Assert.Contains("APT29 (Cozy Bear)", json);
            Assert.Contains("198.51.100.24", json);
            Assert.Contains("T1003.001", json);
        }

        [Fact]
        public async Task AmcacheAndEvtxCarver_ParseAndCarveArtifacts()
        {
            var amcacheParser = new AmcacheShimcacheParser();
            var carver = new EvtxCarverEngine();

            string tempAmcache = Path.Combine(Path.GetTempPath(), "Amcache.hve");
            string tempRawDisk = Path.Combine(Path.GetTempPath(), "unallocated_chunk.raw");

            try
            {
                File.WriteAllBytes(tempAmcache, new byte[2048]);
                
                // Construim un payload sintetic ce conține "ElfChnk\0" și "**\0\0"
                var rawBytes = new List<byte>();
                rawBytes.AddRange(new byte[100]);
                rawBytes.AddRange(Encoding.ASCII.GetBytes("ElfChnk\0"));
                rawBytes.AddRange(new byte[200]);
                rawBytes.AddRange(new byte[] { 0x2a, 0x2a, 0x00, 0x00 });
                rawBytes.AddRange(new byte[100]);
                File.WriteAllBytes(tempRawDisk, rawBytes.ToArray());

                Assert.True(amcacheParser.CanParse(tempAmcache));

                var amcacheResults = await amcacheParser.ParseAsync(tempAmcache, "HOST-01");
                Assert.NotEmpty(amcacheResults);
                Assert.Equal("Amcache.hve (Istoric Executabile & Hash-uri)", amcacheResults[0].ArtifactType);

                var carvedResults = await carver.CarveEvtxRecordsAsync(tempRawDisk);
                Assert.NotNull(carvedResults);
                Assert.Equal(2, carvedResults.Count);
                Assert.Contains(carvedResults, c => c.ChunkSignature == "ElfChnk Header");
                Assert.Contains(carvedResults, c => c.ChunkSignature == "EVTX Record Magic (**)");
            }
            finally
            {
                if (File.Exists(tempAmcache)) File.Delete(tempAmcache);
                if (File.Exists(tempRawDisk)) File.Delete(tempRawDisk);
            }
        }
    }
}
