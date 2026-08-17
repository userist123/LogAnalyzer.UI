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
        public string ArtifactCategory => "Compatibilitate & Amcache (Execuție)";
        public string SupportedExtension => ".hve";

        public bool CanParse(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return false;
            string name = Path.GetFileName(filePath).ToLowerInvariant();
            return name.Contains("amcache") || name.Contains("appcompatcache") || name.EndsWith(".hve");
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
                    string fileName = Path.GetFileName(filePath);
                    DateTime fileDate = File.GetLastWriteTimeUtc(filePath);

                    if (fileName.Contains("amcache", StringComparison.OrdinalIgnoreCase))
                    {
                        var amcacheArtifact = new ForensicArtifact
                        {
                            HostId = hostId,
                            ArtifactType = "Amcache.hve",
                            Name = "Amcache Application Inventory",
                            SourceFilePath = filePath,
                            SourceSha256 = sha256,
                            Timestamp = fileDate,
                            TimestampSemantics = TimeSemantics.Recorded,
                            Strength = EvidenceStrength.ExecutionProven,
                            Summary = $"Artefact Amcache.hve cules de pe [{hostId}]. Păstrează istoricul executabilelor rulate, versiunile, căile de disc și hash-urile SHA-1/SHA-256.",
                            MitreTechniqueId = "T1059",
                            Properties = new Dictionary<string, string>
                            {
                                { "Tip Artefact", "Amcache.hve Registry Hive" },
                                { "Forță Probatorie", "Execuție Certă (Execution Proven)" },
                                { "Notă Juridică", "Furnizează legătura de necontestat între binarul executat, hash-ul acestuia și momentul instalării/rulării." }
                            }
                        };
                        results.Add(amcacheArtifact);
                    }
                    else
                    {
                        var shimArtifact = new ForensicArtifact
                        {
                            HostId = hostId,
                            ArtifactType = "Shimcache (AppCompatCache)",
                            Name = "Application Compatibility Cache",
                            SourceFilePath = filePath,
                            SourceSha256 = sha256,
                            Timestamp = fileDate,
                            TimestampSemantics = TimeSemantics.Modified,
                            Strength = EvidenceStrength.ExecutionPossible,
                            Summary = $"Artefact Shimcache cules de pe [{hostId}]. Pe Windows 10/11, prezența unei intrări probează existența fișierului și inserarea în cache, dar NU garantează execuția efectivă fără coroborare cu Prefetch/Amcache.",
                            MitreTechniqueId = "T1059",
                            Properties = new Dictionary<string, string>
                            {
                                { "Tip Artefact", "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache" },
                                { "Forță Probatorie", "Execuție Posibilă / Existență Fișier (Execution Possible)" },
                                { "Avertisment Interpretare (Mandiant/nullsec.us)", "Pe Windows 10/11 flag-ul de execuție din Shimcache nu mai este actualizat de OS; necesită Prefetch pentru confirmare certă." }
                            }
                        };
                        results.Add(shimArtifact);
                    }
                }
                catch { }
            }, cancellationToken);

            return results;
        }

        private static string ComputeFileSha256(string filePath)
        {
            using var sha = SHA256.Create();
            using var stream = File.OpenRead(filePath);
            return Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
        }
    }
}
