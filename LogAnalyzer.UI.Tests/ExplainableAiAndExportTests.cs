using System;
using System.Collections.Generic;
using System.IO;
using LogAnalyzer.Core.Models;
using LogAnalyzer.Core.Services;
using Xunit;

namespace LogAnalyzer.UI.Tests
{
    public class ExplainableAiAndExportTests
    {
        [Fact]
        public void ExplainableAiRiskEngine_ComputesWeightedScoreAndFactors()
        {
            var engine = new ExplainableAiRiskEngine();
            var issues = new List<DetectedIssue>
            {
                new DetectedIssue
                {
                    Title = "Test Kerberoasting",
                    Severity = "High",
                    MitreTechniqueId = "T1558.003",
                    Explanation = "RC4 encryption requested in TGS ticket."
                }
            };

            var assessment = engine.Evaluate(issues, highEntropyCount: 2, masqueradingCount: 1, offHoursCount: 1, yaraMatchesCount: 1);

            Assert.NotNull(assessment);
            Assert.True(assessment.TotalScore > 0 && assessment.TotalScore <= 100);
            Assert.NotEmpty(assessment.Factors);
            Assert.Contains(assessment.Factors, f => f.MitreTechniqueId == "T1027");
            Assert.Contains(assessment.Factors, f => f.MitreTechniqueId == "T1036.003");
            Assert.False(string.IsNullOrWhiteSpace(assessment.ExecutiveSummaryRo));
        }

        [Fact]
        public void CaseUcoExportService_GeneratesValidJsonLdOntology()
        {
            var exportService = new CaseUcoExportService();
            var artifacts = new List<ForensicArtifact>
            {
                new ForensicArtifact
                {
                    Id = Guid.NewGuid().ToString(),
                    Name = "PassTheHash.exe",
                    ArtifactType = "Prefetch Execution",
                    SourceFilePath = "C:\\Windows\\Prefetch\\PASSTHEHASH.EXE-12345.pf",
                    SourceSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                    Timestamp = DateTime.UtcNow,
                    Strength = EvidenceStrength.ExecutionProven
                }
            };

            string jsonLd = exportService.ExportCaseJsonLd("CASE-2026-001", "Operator SOC", "CERT-RO", artifacts, new List<ProvenanceLedgerEntry>());

            Assert.NotNull(jsonLd);
            Assert.Contains("@context", jsonLd);
            Assert.Contains("uco-core", jsonLd);
            Assert.Contains("CASE-2026-001", jsonLd);
        }

        [Fact]
        public void SuperTimelineExportService_GeneratesValidPlasoCsv()
        {
            var exportService = new SuperTimelineExportService();
            var events = new List<ParsedEvent>
            {
                new ParsedEvent
                {
                    TimeCreated = DateTime.UtcNow,
                    ProviderName = "Microsoft-Windows-Security-Auditing",
                    EventId = 4624,
                    Level = "Information",
                    MachineName = "ADMIN-PC",
                    Message = "Successful Logon Event ID 4624"
                }
            };

            string tempCsv = Path.Combine(Path.GetTempPath(), $"timeline_test_{Guid.NewGuid():N}.csv");
            try
            {
                exportService.ExportPlasoCsv(tempCsv, events, new List<ForensicArtifact>(), new List<RegistryArtifact>());
                Assert.True(File.Exists(tempCsv));
                string content = File.ReadAllText(tempCsv);
                Assert.Contains("Date,Time,Timezone,MACB,Source,SourceType,Type,User,Host,Short,Desc,Version,Filename,Inode,Notes,Format,Extra", content);
                Assert.Contains("Successful Logon Event ID 4624", content);
            }
            finally
            {
                if (File.Exists(tempCsv)) File.Delete(tempCsv);
            }
        }
    }
}
