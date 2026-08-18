using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Infrastructure.Parsers
{
    public class CrossPlatformLogsParser : IForensicArtifactParser
    {
        public string ArtifactCategory => "Cross-Platform (Linux auditd / macOS)";
        public string SupportedExtension => ".log";

        public bool CanParse(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return false;
            string name = Path.GetFileName(filePath).ToLowerInvariant();
            return name.Contains("audit.log") || name.Contains("auditd") || name.Contains("syslog") || name.Contains("secure") || name.Contains("messages") || name.Contains("logarchive");
        }

        public async Task<List<ForensicArtifact>> ParseAsync(string filePath, string hostId, CancellationToken cancellationToken = default)
        {
            var results = new List<ForensicArtifact>();
            if (!File.Exists(filePath)) return results;

            await Task.Run(() =>
            {
                try
                {
                    string sha256 = ComputeFileSha256(filePath);
                    var lines = File.ReadAllLines(filePath);
                    var execveRegex = new Regex(@"type=EXECVE.*a0=""?([^""\s]+)""?", RegexOptions.Compiled);
                    var syscallRegex = new Regex(@"type=SYSCALL.*exe=""?([^""\s]+)""?", RegexOptions.Compiled);
                    int count = 0;

                    foreach (var line in lines)
                    {
                        if (line.Contains("type=EXECVE") || line.Contains("type=SYSCALL"))
                        {
                            var matchExec = execveRegex.Match(line);
                            var matchSys = syscallRegex.Match(line);

                            string binary = matchExec.Success ? matchExec.Groups[1].Value : (matchSys.Success ? matchSys.Groups[1].Value : "linux_binary");

                            results.Add(new ForensicArtifact
                            {
                                HostId = hostId,
                                ArtifactType = "Linux auditd Execve / Syscall",
                                Name = Path.GetFileName(binary),
                                SourceFilePath = filePath,
                                SourceSha256 = sha256,
                                Timestamp = File.GetLastWriteTimeUtc(filePath),
                                TimestampSemantics = TimeSemantics.Recorded,
                                Strength = EvidenceStrength.ExecutionProven,
                                Summary = $"[LINUX AUDITD] Execuție proces '{binary}' înregistrată de kernelul Linux. Linie audit: {line.Trim()}",
                                MitreTechniqueId = "T1059.004",
                                Properties = new Dictionary<string, string>
                                {
                                    { "Cale Executabil", binary },
                                    { "Linie Log", line.Trim() },
                                    { "Forță Probatorie", "Execuție Certă (Linux Kernel Audit Framework)" }
                                }
                            });
                            count++;
                            if (count >= 30) break;
                        }
                    }

                    if (results.Count == 0)
                    {
                        results.Add(new ForensicArtifact
                        {
                            HostId = hostId,
                            ArtifactType = "Cross-Platform System Log",
                            Name = Path.GetFileName(filePath),
                            SourceFilePath = filePath,
                            SourceSha256 = sha256,
                            Timestamp = File.GetLastWriteTimeUtc(filePath),
                            TimestampSemantics = TimeSemantics.Recorded,
                            Strength = EvidenceStrength.ExecutionPossible,
                            Summary = $"Jurnal Linux/macOS [{Path.GetFileName(filePath)}] importat pentru corelare timeline.",
                            MitreTechniqueId = "T1059",
                            Properties = new Dictionary<string, string> { { "Sursă", filePath } }
                        });
                    }
                }
                catch { }
            }, cancellationToken);

            return results;
        }

        private static string ComputeFileSha256(string filePath)
        {
            using var sha = SHA256.Create();
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
        }
    }
}
