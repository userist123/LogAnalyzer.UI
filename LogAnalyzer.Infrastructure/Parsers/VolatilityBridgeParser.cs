using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Infrastructure.Parsers
{
    public class VolatilityBridgeParser : IForensicArtifactParser
    {
        public string ArtifactCategory => "Analiză Memorie RAM (Volatility 3)";
        public string SupportedExtension => ".json";

        public bool CanParse(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return false;
            string name = Path.GetFileName(filePath).ToLowerInvariant();
            return name.Contains("volatility") || name.Contains("pslist") || name.Contains("malfind") || name.Contains("netscan") || name.Contains("vadinfo");
        }

        public async Task<List<ForensicArtifact>> ParseAsync(string filePath, string hostId, CancellationToken cancellationToken = default)
        {
            var results = new List<ForensicArtifact>();
            if (!File.Exists(filePath)) return results;

            await Task.Run(() =>
            {
                try
                {
                    string content = File.ReadAllText(filePath);
                    string sha256 = ComputeFileSha256(filePath);
                    string fileName = Path.GetFileName(filePath).ToLowerInvariant();

                    if (fileName.Contains("malfind"))
                    {
                        // Parsăm detecțiile de memorie injectată (PAGE_EXECUTE_READWRITE)
                        var doc = JsonDocument.Parse(content);
                        int injectCount = 0;

                        if (doc.RootElement.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var element in doc.RootElement.EnumerateArray())
                            {
                                string pid = element.TryGetProperty("PID", out var p) ? p.ToString() : "N/A";
                                string process = element.TryGetProperty("Process", out var pr) ? pr.GetString() ?? "Unknown" : "Unknown";
                                string protection = element.TryGetProperty("Protection", out var prot) ? prot.GetString() ?? "PAGE_EXECUTE_READWRITE" : "PAGE_EXECUTE_READWRITE";
                                string startVpn = element.TryGetProperty("Start VPN", out var vpn) ? vpn.ToString() : "0x0";

                                results.Add(new ForensicArtifact
                                {
                                    HostId = hostId,
                                    ArtifactType = "Injecție Memorie RAM (Volatility malfind)",
                                    Name = $"{process} (PID {pid})",
                                    SourceFilePath = filePath,
                                    SourceSha256 = sha256,
                                    Timestamp = File.GetLastWriteTimeUtc(filePath),
                                    TimestampSemantics = TimeSemantics.BatchFlushed,
                                    Strength = EvidenceStrength.ExecutionProven,
                                    Summary = $"[RAM VOLATILITY] Detectată regiune de memorie injectată ({protection}) în procesul '{process}' (PID {pid}) la adresa {startVpn}.",
                                    MitreTechniqueId = "T1055.012",
                                    Properties = new Dictionary<string, string>
                                    {
                                        { "Proces Țintă", process },
                                        { "PID", pid },
                                        { "Protecție Pagină VAD", protection },
                                        { "Adresă Memorie", startVpn },
                                        { "Forță Probatorie", "Execuție Certă în Memoria RAM a Procesului" }
                                    }
                                });
                                injectCount++;
                                if (injectCount >= 30) break;
                            }
                        }
                    }
                    else
                    {
                        // Generic Volatility 3 Plugin Output
                        results.Add(new ForensicArtifact
                        {
                            HostId = hostId,
                            ArtifactType = "Telemetrie RAM (Volatility 3)",
                            Name = Path.GetFileName(filePath),
                            SourceFilePath = filePath,
                            SourceSha256 = sha256,
                            Timestamp = File.GetLastWriteTimeUtc(filePath),
                            TimestampSemantics = TimeSemantics.BatchFlushed,
                            Strength = EvidenceStrength.ExecutionProven,
                            Summary = $"Export de analiză memorie RAM Volatility 3 [{Path.GetFileName(filePath)}] pentru investigarea proceselor și conexiunilor active.",
                            MitreTechniqueId = "T1057",
                            Properties = new Dictionary<string, string>
                            {
                                { "Plugin Volatility", Path.GetFileNameWithoutExtension(filePath) },
                                { "Sursă Dump", filePath }
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
