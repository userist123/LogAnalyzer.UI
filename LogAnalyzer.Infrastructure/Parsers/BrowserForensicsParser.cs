using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Models;
using Microsoft.Data.Sqlite;

namespace LogAnalyzer.Infrastructure.Parsers
{
    public class BrowserForensicsParser : IForensicArtifactParser
    {
        public string ArtifactCategory => "Navigare Web & Descărcări (Browser Forensics)";
        public string SupportedExtension => ".sqlite";

        public bool CanParse(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return false;
            string name = Path.GetFileName(filePath).ToLowerInvariant();
            return name.Contains("history") || name.Contains("places.sqlite") || name.Contains("webcache") || name.EndsWith(".sqlite");
        }

        public async Task<List<ForensicArtifact>> ParseAsync(string filePath, string hostId, CancellationToken cancellationToken = default)
        {
            var results = new List<ForensicArtifact>();
            if (!File.Exists(filePath)) return results;

            await Task.Run(() =>
            {
                // Pentru a evita blocajele de fișier și a include fișierele WAL, copiem baza într-un temp
                string tempDir = Path.Combine(Path.GetTempPath(), "DFIR_Browser_" + Guid.NewGuid().ToString("N"));
                Directory.CreateDirectory(tempDir);
                string tempDbPath = Path.Combine(tempDir, Path.GetFileName(filePath));

                try
                {
                    File.Copy(filePath, tempDbPath, true);
                    string walSrc = filePath + "-wal";
                    if (File.Exists(walSrc)) File.Copy(walSrc, tempDbPath + "-wal", true);
                    string shmSrc = filePath + "-shm";
                    if (File.Exists(shmSrc)) File.Copy(shmSrc, tempDbPath + "-shm", true);

                    string sha256 = ComputeFileSha256(filePath);

                    using var conn = new SqliteConnection($"Data Source={tempDbPath};Mode=ReadOnly;");
                    conn.Open();

                    // 1. Verificăm dacă este Chrome/Edge (tabelul 'urls')
                    using var cmd = conn.CreateCommand();
                    cmd.CommandText = "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 100;";
                    
                    try
                    {
                        using var reader = cmd.ExecuteReader();
                        while (reader.Read())
                        {
                            string url = reader.GetString(0);
                            string title = reader.IsDBNull(1) ? "Fără titlu" : reader.GetString(1);
                            int visitCount = reader.GetInt32(2);
                            long chromeTime = reader.GetInt64(3);
                            
                            DateTime visitUtc = DateTime.UtcNow;
                            if (chromeTime > 0)
                            {
                                // Chrome time este microsecunde de la 1601-01-01
                                try { visitUtc = DateTime.FromFileTimeUtc(chromeTime * 10); } catch { }
                            }

                            results.Add(new ForensicArtifact
                            {
                                HostId = hostId,
                                ArtifactType = "Browser History (Chrome/Edge)",
                                Name = title,
                                SourceFilePath = filePath,
                                SourceSha256 = sha256,
                                Timestamp = visitUtc,
                                TimestampSemantics = TimeSemantics.Recorded,
                                Strength = EvidenceStrength.ExecutionProven,
                                Summary = $"Navigare URL: [{url}] ({title}). Număr vizite: {visitCount}. Data: {visitUtc:yyyy-MM-dd HH:mm:ss} UTC.",
                                MitreTechniqueId = "T1071.001",
                                Properties = new Dictionary<string, string>
                                {
                                    { "URL", url },
                                    { "Titlu Pagină", title },
                                    { "Vizite", visitCount.ToString() },
                                    { "Data Vizitei (UTC)", visitUtc.ToString("yyyy-MM-dd HH:mm:ss") }
                                }
                            });
                        }
                    }
                    catch { }
                }
                catch { }
                finally
                {
                    try { Directory.Delete(tempDir, true); } catch { }
                }
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
