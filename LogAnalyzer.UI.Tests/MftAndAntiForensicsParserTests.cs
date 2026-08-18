using System;
using System.IO;
using System.Threading.Tasks;
using LogAnalyzer.Core.Models;
using LogAnalyzer.Infrastructure.Parsers;
using Xunit;

namespace LogAnalyzer.UI.Tests
{
    public class MftAndAntiForensicsParserTests
    {
        [Fact]
        public async Task MftParser_CanParse_AndReturnsValidArtifact()
        {
            var parser = new MftParser();
            string tempFile = Path.Combine(Path.GetTempPath(), "test_$MFT.tmp");
            try
            {
                // Scriem un buffer de test
                byte[] dummyMft = new byte[2048];
                dummyMft[0] = 0x46; // 'F'
                dummyMft[1] = 0x49; // 'I'
                dummyMft[2] = 0x4C; // 'L'
                dummyMft[3] = 0x45; // 'E'
                File.WriteAllBytes(tempFile, dummyMft);

                Assert.True(parser.CanParse(tempFile));

                var results = await parser.ParseAsync(tempFile, "SEC-WORKSTATION-01");
                Assert.NotNull(results);
                Assert.NotEmpty(results);
                Assert.Equal("SEC-WORKSTATION-01", results[0].HostId);
                Assert.Equal(EvidenceStrength.FileExistenceOnly, results[0].Strength);
            }
            finally
            {
                if (File.Exists(tempFile)) File.Delete(tempFile);
            }
        }

        [Fact]
        public async Task AntiForensicsParser_ParsesMpLog_ExtractsThreatAndSha256()
        {
            var parser = new AntiForensicsArtifactsParser();
            string tempLog = Path.Combine(Path.GetTempPath(), "MPLog-20260818.log");
            try
            {
                string dummySha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
                string logContent = $"2026-08-18T10:00:00.000Z Threat:Trojan:Win32/Mimikatz.A Quarantine path: C:\\Windows\\Temp\\mimikatz.exe SHA-256: {dummySha}";
                File.WriteAllText(tempLog, logContent);

                Assert.True(parser.CanParse(tempLog));

                var results = await parser.ParseAsync(tempLog, "SOC-HOST-02");
                Assert.NotNull(results);
                Assert.NotEmpty(results);
                Assert.Contains("MPLog", results[0].ArtifactType);
                Assert.Equal(EvidenceStrength.ExecutionProven, results[0].Strength);
                Assert.Equal(dummySha, results[0].Properties["Hash SHA-256 Extras"]);
            }
            finally
            {
                if (File.Exists(tempLog)) File.Delete(tempLog);
            }
        }

        [Fact]
        public async Task AntiForensicsParser_ParsesPcaLog_ExtractsExecutionTime()
        {
            var parser = new AntiForensicsArtifactsParser();
            string tempPca = Path.Combine(Path.GetTempPath(), "PcaAppLaunchDic.txt");
            try
            {
                string content = "C:\\Tools\\psexec.exe|2026-08-18 12:30:00.000\nC:\\Windows\\System32\\cmd.exe|2026-08-18 12:31:00.000";
                File.WriteAllText(tempPca, content);

                Assert.True(parser.CanParse(tempPca));

                var results = await parser.ParseAsync(tempPca, "DC-SERVER-01");
                Assert.NotNull(results);
                Assert.Equal(2, results.Count);
                Assert.Equal("psexec.exe", results[0].Name);
                Assert.Equal(EvidenceStrength.ExecutionProven, results[0].Strength);
            }
            finally
            {
                if (File.Exists(tempPca)) File.Delete(tempPca);
            }
        }
    }
}
