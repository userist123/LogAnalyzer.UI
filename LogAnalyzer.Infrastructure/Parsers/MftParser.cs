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
    public class MftParser : IForensicArtifactParser
    {
        public string ArtifactCategory => "Sistem de Fișiere NTFS ($MFT)";
        public string SupportedExtension => "$MFT";

        public bool CanParse(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return false;
            string name = Path.GetFileName(filePath).ToUpperInvariant();
            return name == "$MFT" || name.EndsWith(".MFT") || name.Contains("MFT");
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
                    var fileInfo = new FileInfo(filePath);

                    var mftArtifact = new ForensicArtifact
                    {
                        HostId = hostId,
                        ArtifactType = "NTFS $MFT",
                        Name = "Master File Table ($MFT)",
                        SourceFilePath = filePath,
                        SourceSha256 = sha256,
                        Timestamp = fileInfo.LastWriteTimeUtc,
                        TimestampSemantics = TimeSemantics.Recorded,
                        Strength = EvidenceStrength.FileExistenceOnly,
                        Summary = $"Tabela Master File Table ($MFT) culeasă de pe [{hostId}]. Permite reconstrucția istoricului tuturor fișierelor create, șterse sau modificate pe volumul NTFS.",
                        MitreTechniqueId = "T1070.006",
                        Properties = new Dictionary<string, string>
                        {
                            { "Dimensiune $MFT", $"{fileInfo.Length / (1024 * 1024):N1} MB" },
                            { "Forță Probatorie", "Existență Fișier / Metadate NTFS (File Existence)" },
                            { "Capabilitate Anti-Forensics", "Detectare Timestomping prin diferența dintre atributele $STANDARD_INFORMATION și $FILE_NAME." }
                        }
                    };
                    results.Add(mftArtifact);
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
