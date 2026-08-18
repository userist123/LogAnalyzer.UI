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
    public class M365EntraIdLogsParser : IForensicArtifactParser
    {
        public string ArtifactCategory => "Cloud & Identitate Hibridă (M365 / Entra ID)";
        public string SupportedExtension => ".json";

        public bool CanParse(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return false;
            string name = Path.GetFileName(filePath).ToLowerInvariant();
            return name.Contains("signin") || name.Contains("entra") || name.Contains("azuread") || name.Contains("auditlogs") || name.Contains("m365");
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

                    var doc = JsonDocument.Parse(content);
                    if (doc.RootElement.ValueKind == JsonValueKind.Array)
                    {
                        foreach (var element in doc.RootElement.EnumerateArray())
                        {
                            string user = element.TryGetProperty("userPrincipalName", out var upn) ? upn.GetString() ?? "Unknown" : "Unknown";
                            string ip = element.TryGetProperty("ipAddress", out var ipProp) ? ipProp.GetString() ?? "-" : "-";
                            string country = "-";
                            string city = "-";

                            if (element.TryGetProperty("location", out var loc))
                            {
                                if (loc.TryGetProperty("countryOrRegion", out var c)) country = c.GetString() ?? "-";
                                if (loc.TryGetProperty("city", out var ct)) city = ct.GetString() ?? "-";
                            }

                            string status = "Success";
                            if (element.TryGetProperty("status", out var st) && st.TryGetProperty("errorCode", out var ec))
                            {
                                if (ec.GetInt32() != 0) status = $"Failed (Error {ec.GetInt32()})";
                            }

                            results.Add(new ForensicArtifact
                            {
                                HostId = "M365-TENANT-CLOUD",
                                ArtifactType = "Entra ID Sign-in Telemetry",
                                Name = $"Autentificare {user}",
                                SourceFilePath = filePath,
                                SourceSha256 = sha256,
                                Timestamp = File.GetLastWriteTimeUtc(filePath),
                                TimestampSemantics = TimeSemantics.Recorded,
                                Strength = EvidenceStrength.ExecutionProven,
                                Summary = $"[M365 CLOUD] Autentificare utilizator '{user}' de la IP {ip} ({city}, {country}) - Rezultat: {status}.",
                                MitreTechniqueId = "T1078.004",
                                Properties = new Dictionary<string, string>
                                {
                                    { "Utilizator UPN", user },
                                    { "IP Sursă", ip },
                                    { "Locație Geografică", $"{city}, {country}" },
                                    { "Status Autentificare", status },
                                    { "Forță Probatorie", "Jurnal de Autentificare Cloud Cert" }
                                }
                            });
                        }
                    }
                    else
                    {
                        results.Add(new ForensicArtifact
                        {
                            HostId = "M365-TENANT-CLOUD",
                            ArtifactType = "Audit Log Cloud Entra ID",
                            Name = Path.GetFileName(filePath),
                            SourceFilePath = filePath,
                            SourceSha256 = sha256,
                            Timestamp = File.GetLastWriteTimeUtc(filePath),
                            TimestampSemantics = TimeSemantics.Recorded,
                            Strength = EvidenceStrength.ExecutionProven,
                            Summary = $"Jurnal de audit administrativ Microsoft 365 / Entra ID importat pentru investigare.",
                            MitreTechniqueId = "T1098",
                            Properties = new Dictionary<string, string>
                            {
                                { "Sursă Fișier", filePath }
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
