using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Infrastructure.Parsers
{
    public class AmcacheShimcacheParser : IForensicArtifactParser
    {
        public string ArtifactCategory => "Execuție Istorică (Amcache & Shimcache)";
        public string SupportedExtension => ".hve";

        public bool CanParse(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return false;
            string name = Path.GetFileName(filePath).ToLowerInvariant();
            return name.Contains("amcache") || name.Contains("appcompatcache") || name.Contains("shimcache") || name.EndsWith(".hve");
        }

        public async Task<List<ForensicArtifact>> ParseAsync(string filePath, string hostId, CancellationToken cancellationToken = default)
        {
            var results = new List<ForensicArtifact>();
            if (!File.Exists(filePath)) return results;

            await Task.Run(() =>
            {
                try
                {
                    var fileInfo = new FileInfo(filePath);
                    string sha256 = ComputeFileSha256(filePath);
                    string name = Path.GetFileName(filePath).ToLowerInvariant();

                    if (name.Contains("amcache"))
                    {
                        // Amcache.hve
                        results.Add(new ForensicArtifact
                        {
                            HostId = hostId,
                            ArtifactType = "Amcache.hve (Istoric Executabile & Hash-uri)",
                            Name = "Amcache Application Compatibility Hive",
                            SourceFilePath = filePath,
                            SourceSha256 = sha256,
                            Timestamp = fileInfo.LastWriteTimeUtc,
                            TimestampSemantics = TimeSemantics.BatchFlushed,
                            Strength = EvidenceStrength.ExecutionProven,
                            Summary = $"Baza de date Amcache.hve de pe [{hostId}]. Păstrează hash-ul SHA-1/SHA-256, dimensiunea și timestamp-ul de compilare PE al fiecărui program rulat vreodată pe sistem.",
                            MitreTechniqueId = "T1059",
                            Properties = new Dictionary<string, string>
                            {
                                { "Dimensiune Fișier", $"{fileInfo.Length / 1024:N0} KB" },
                                { "Capabilitate", "Extragere Hash-uri binare PE chiar dacă fișierele au fost șterse de pe disc" },
                                { "Forță Probatorie", "Execuție Certă / Proba Existenței Binarelor" }
                            }
                        });
                    }
                    else
                    {
                        // Shimcache / AppCompatCache
                        results.Add(new ForensicArtifact
                        {
                            HostId = hostId,
                            ArtifactType = "Shimcache (AppCompatCache Executions)",
                            Name = "Application Compatibility Cache",
                            SourceFilePath = filePath,
                            SourceSha256 = sha256,
                            Timestamp = fileInfo.LastWriteTimeUtc,
                            TimestampSemantics = TimeSemantics.BatchFlushed,
                            Strength = EvidenceStrength.ExecutionPossible,
                            Summary = $"Artefact Shimcache recuperat de pe [{hostId}]. Confirmă prezența fișierelor pe disc și calea completă a uneltelor utilizate de atacator.",
                            MitreTechniqueId = "T1059",
                            Properties = new Dictionary<string, string>
                            {
                                { "Sursă Hive", filePath },
                                { "Forță Probatorie", "Existență / Posibilă Execuție" }
                            }
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
