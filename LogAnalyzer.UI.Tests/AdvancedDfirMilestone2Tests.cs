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
    public class AdvancedDfirMilestone2Tests
    {
        [Fact]
        public void TimelineDiffEngine_IsolatesUnseenSuspectEvents()
        {
            var engine = new TimelineDiffEngine();

            var baseline = new List<TimelineItem>
            {
                new TimelineItem { Source = "EVTX", Category = "Logon", Description = "Legitimate user logon" }
            };

            var suspect = new List<TimelineItem>
            {
                new TimelineItem { Source = "EVTX", Category = "Logon", Description = "Legitimate user logon" },
                new TimelineItem { Source = "EVTX", Category = "Process", Description = "Suspicious powershell -enc execution" }
            };

            var diff = engine.CompareTimelines(suspect, baseline);

            Assert.NotNull(diff);
            Assert.Equal(1, diff.TotalDiffCount);
            Assert.Equal("Suspicious powershell -enc execution", diff.NewOrInjectedEvents[0].Description);
            Assert.Equal(1, diff.CommonBaselineEvents.Count);
        }

        [Fact]
        public void EntropyFeatureExtractor_DetectsBase64Obfuscation()
        {
            var extractor = new EntropyFeatureExtractor();
            string obfuscatedScript = "$x = [System.Convert]::FromBase64String('aGVsbG8gd29ybGQgdGhpcyBpcyBhIHRlc3Qgb2YgcG93ZXJzaGVsbCBvYmZ1c2NhdGlvbiBwYXlsb2FkIGluamVjdGlvbg=='); IEX $x";

            var analysis = extractor.AnalyzeText(obfuscatedScript);

            Assert.NotNull(analysis);
            Assert.True(analysis.IsLikelyObfuscated);
            Assert.Equal("Critical", analysis.RiskScoreLevel);
            Assert.Contains("Base64", analysis.ObfuscationKind);
        }

        [Fact]
        public void KerberosAdAttackEngine_DetectsDcSyncAndAsRepRoasting()
        {
            var engine = new KerberosAdAttackEngine();
            var events = new List<ParsedEvent>
            {
                new ParsedEvent
                {
                    EventId = 4662,
                    TimeCreated = DateTime.UtcNow,
                    Message = "An operation was performed on an object. Properties: {1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}"
                },
                new ParsedEvent
                {
                    EventId = 4768,
                    TimeCreated = DateTime.UtcNow.AddMinutes(1),
                    Message = "A Kerberos authentication ticket (TGT) was requested. Pre-Authentication Type: 0"
                }
            };

            var findings = engine.AnalyzeEvents(events);

            Assert.NotNull(findings);
            Assert.Contains(findings, f => f.MitreTechniqueId == "T1003.006"); // DCSync
            Assert.Contains(findings, f => f.MitreTechniqueId == "T1558.004"); // AS-REP Roasting
        }

        [Fact]
        public async Task SrumAndRdpParsers_IdentifyAndParseArtifacts()
        {
            var srumParser = new SrumParser();
            var rdpParser = new RdpBitmapCacheParser();

            string tempSrum = Path.Combine(Path.GetTempPath(), "test_SRUDB.dat");
            string tempRdp = Path.Combine(Path.GetTempPath(), "bcache24.bmc");

            try
            {
                File.WriteAllBytes(tempSrum, new byte[1024]);
                File.WriteAllBytes(tempRdp, new byte[1024]);

                Assert.True(srumParser.CanParse(tempSrum));
                Assert.True(rdpParser.CanParse(tempRdp));

                var srumResults = await srumParser.ParseAsync(tempSrum, "HOST-01");
                var rdpResults = await rdpParser.ParseAsync(tempRdp, "HOST-01");

                Assert.NotEmpty(srumResults);
                Assert.Equal("SRUM Network & Resource Usage", srumResults[0].ArtifactType);

                Assert.NotEmpty(rdpResults);
                Assert.Equal("RDP Bitmap Cache", rdpResults[0].ArtifactType);
            }
            finally
            {
                if (File.Exists(tempSrum)) File.Delete(tempSrum);
                if (File.Exists(tempRdp)) File.Delete(tempRdp);
            }
        }
    }
}
