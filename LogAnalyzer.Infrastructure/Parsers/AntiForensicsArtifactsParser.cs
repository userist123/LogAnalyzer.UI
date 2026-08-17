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
        public string ArtifactCategory => "Anti-Forensics, Defender MPLog & UserAssist";
        public string SupportedExtension => ".log";

        public bool CanParse(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return false;
            string name = Path.GetFileName(filePath).ToLowerInvariant();
            return name.Contains("mplog") || name.Contains("userassist") || name.Contains("pca") || name.Contains("eventtranscript");
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

                    if (fileName.Contains("mplog"))
                    {
                        // Parsăm fișierul Microsoft Protection Log (MPLog) pentru extragere de SHA-256 al malware-ului șters
                        var lines = File.ReadAllLines(filePath);
                        var shaRegex = new Regex(@"[0-9a-fA-F]{64}", RegexOptions.Compiled);
                        int extractedHashes = 0;

                        foreach (var line in lines)
                        {
                            if (line.Contains("Threat") || line.Contains("Quarantine") || line.Contains("Detection"))
                            {
                                var match = shaRegex.Match(line);
                                string foundSha = match.Success ? match.Value : "-";

                                results.Add(new ForensicArtifact
                                {
                                    HostId = hostId,
                                    ArtifactType = "Defender MPLog",
                                    Name = "Detecție & Carantină Malware",
                                    SourceFilePath = filePath,
                                    SourceSha256 = sha256,
                                    Timestamp = File.GetLastWriteTimeUtc(filePath),
                                    TimestampSemantics = TimeSemantics.Recorded,
                                    Strength = EvidenceStrength.ExecutionProven,
                                    Summary = $"Jurnal Defender MPLog: {line.Trim()}",
                                    MitreTechniqueId = "T1562.001",
                                    Properties = new Dictionary<string, string>
                                    {
                                        { "Linie MPLog", line.Trim() },
                                        { "Hash SHA-256 extras", foundSha },
                                        { "Forță Probatorie", "Execuție Certă / Interceptare Antivirus" }
                                    }
                                });
                                extractedHashes++;
                                if (extractedHashes >= 50) break;
                            }
                        }
                    }
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
            using var stream = File.OpenRead(filePath);
            return Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
        }
    }
}
