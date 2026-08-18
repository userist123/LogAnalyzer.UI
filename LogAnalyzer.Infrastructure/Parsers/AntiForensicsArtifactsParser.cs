using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Infrastructure.Parsers
{
    public class AntiForensicsArtifactsParser : IForensicArtifactParser
    {
        public string ArtifactCategory => "Anti-Forensics, Defender MPLog, EventTranscript & PCA";
        public string SupportedExtension => ".log";

        public bool CanParse(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return false;
            string name = Path.GetFileName(filePath).ToLowerInvariant();
            return name.Contains("mplog") || name.Contains("userassist") || name.Contains("pca") || name.Contains("applaunch") || name.Contains("eventtranscript") || name.EndsWith(".db") || name.EndsWith(".txt") || name.EndsWith(".log");
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
                    string fileName = Path.GetFileName(filePath).ToLowerInvariant();

                    // 1. Microsoft Protection Log (MPLog)
                    if (fileName.Contains("mplog"))
                    {
                        var lines = File.ReadAllLines(filePath);
                        var shaRegex = new Regex(@"[0-9a-fA-F]{64}", RegexOptions.Compiled);
                        var threatRegex = new Regex(@"(?:Threat|Trojan|Backdoor|Ransom|Exploit|Hacktool|Virus|Malware):[\w\./\-]+", RegexOptions.IgnoreCase | RegexOptions.Compiled);
                        int count = 0;

                        foreach (var line in lines)
                        {
                            if (line.Contains("Threat") || line.Contains("Quarantine") || line.Contains("Detection") || line.Contains("Signature"))
                            {
                                var matchSha = shaRegex.Match(line);
                                var matchThreat = threatRegex.Match(line);

                                string foundSha = matchSha.Success ? matchSha.Value : "N/A";
                                string foundThreat = matchThreat.Success ? matchThreat.Value : "Detecție Nespecificată";

                                results.Add(new ForensicArtifact
                                {
                                    HostId = hostId,
                                    ArtifactType = "Defender MPLog (Contra-Anti-Forensics)",
                                    Name = foundThreat,
                                    SourceFilePath = filePath,
                                    SourceSha256 = sha256,
                                    Timestamp = File.GetLastWriteTimeUtc(filePath),
                                    TimestampSemantics = TimeSemantics.Recorded,
                                    Strength = EvidenceStrength.ExecutionProven,
                                    Summary = $"[JURNAL MPLog] Defender a detectat '{foundThreat}'. Hash SHA-256 binar: {foundSha}. Sursă linie: {line.Trim()}",
                                    MitreTechniqueId = "T1562.001",
                                    Properties = new Dictionary<string, string>
                                    {
                                        { "Amenințare", foundThreat },
                                        { "Hash SHA-256 Extras", foundSha },
                                        { "Forță Probatorie", "Execuție Certă / Interceptare Antivirus" },
                                        { "Linie MPLog", line.Trim() }
                                    }
                                });
                                count++;
                                if (count >= 50) break;
                            }
                        }
                    }
                    // 2. PCA (Program Compatibility Assistant - PcaAppLaunchDic.txt pe Win11)
                    else if (fileName.Contains("pca") || fileName.Contains("applaunch"))
                    {
                        var lines = File.ReadAllLines(filePath);
                        foreach (var line in lines)
                        {
                            if (string.IsNullOrWhiteSpace(line) || line.Trim().StartsWith("#")) continue;

                            var parts = line.Split('|');
                            string exePath = parts[0].Trim();
                            DateTime launchTime = DateTime.UtcNow;

                            if (parts.Length > 1 && DateTime.TryParse(parts[1], out var parsedDt))
                            {
                                launchTime = parsedDt.ToUniversalTime();
                            }

                            results.Add(new ForensicArtifact
                            {
                                HostId = hostId,
                                ArtifactType = "PCA Program Compatibility Execution",
                                Name = Path.GetFileName(exePath),
                                SourceFilePath = filePath,
                                SourceSha256 = sha256,
                                Timestamp = launchTime,
                                TimestampSemantics = TimeSemantics.LastExecution,
                                Strength = EvidenceStrength.ExecutionProven,
                                Summary = $"Execuție înregistrată de PCA (Windows 11): '{exePath}' la {launchTime:yyyy-MM-dd HH:mm:ss} UTC.",
                                MitreTechniqueId = "T1059",
                                Properties = new Dictionary<string, string>
                                {
                                    { "Cale Executabil", exePath },
                                    { "Data Execuției (UTC)", launchTime.ToString("yyyy-MM-dd HH:mm:ss") },
                                    { "Forță Probatorie", "Execuție Certă (PCA Engine)" }
                                }
                            });
                        }
                    }
                    // 3. EventTranscript.db
                    else if (fileName.Contains("eventtranscript"))
                    {
                        results.Add(new ForensicArtifact
                        {
                            HostId = hostId,
                            ArtifactType = "EventTranscript.db (Supraviețuitor Ștergere Loguri)",
                            Name = "Diagnostic Event Transcript",
                            SourceFilePath = filePath,
                            SourceSha256 = sha256,
                            Timestamp = File.GetLastWriteTimeUtc(filePath),
                            TimestampSemantics = TimeSemantics.Recorded,
                            Strength = EvidenceStrength.ExecutionProven,
                            Summary = $"Baza de date EventTranscript.db recuperată de pe [{hostId}]. Păstrează istoricul de telemetrie chiar dacă evenimentele EVTX au fost șterse de atacator.",
                            MitreTechniqueId = "T1070.001",
                            Properties = new Dictionary<string, string>
                            {
                                { "Sursă Fișier", filePath },
                                { "Dimensiune Bază", $"{new FileInfo(filePath).Length / 1024:N0} KB" },
                                { "Contra-Anti-Forensics", "Rezistent la golirea manuală a canalelor Windows Event Log (EID 1102 / 104)" }
                            }
                        });
                    }
                    // 4. Generic carved
                    else
                    {
                        results.Add(new ForensicArtifact
                        {
                            HostId = hostId,
                            ArtifactType = "Anti-Forensics Carved Artifact",
                            Name = Path.GetFileName(filePath),
                            SourceFilePath = filePath,
                            SourceSha256 = sha256,
                            Timestamp = File.GetLastWriteTimeUtc(filePath),
                            TimestampSemantics = TimeSemantics.Recorded,
                            Strength = EvidenceStrength.ExecutionPossible,
                            Summary = $"Artefact rezidual de execuție/anti-forensics recuperat de pe [{hostId}].",
                            MitreTechniqueId = "T1070",
                            Properties = new Dictionary<string, string>
                            {
                                { "Sursă", filePath },
                                { "Forță Probatorie", "Existență / Execuție Posibilă" }
                            }
                        });
                    }
                }
                catch { }
            }, cancellationToken);

            return results;
        }

        public static string DecodeRot13(string input)
        {
            if (string.IsNullOrEmpty(input)) return string.Empty;
            char[] array = input.ToCharArray();
            for (int i = 0; i < array.Length; i++)
            {
                int number = (int)array[i];
                if (number >= 'a' && number <= 'z')
                {
                    if (number > 'm') number -= 13;
                    else number += 13;
                }
                else if (number >= 'A' && number <= 'Z')
                {
                    if (number > 'M') number -= 13;
                    else number += 13;
                }
                array[i] = (char)number;
            }
            return new string(array);
        }

        private static string ComputeFileSha256(string filePath)
        {
            using var sha = SHA256.Create();
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            return Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
        }
    }
}
