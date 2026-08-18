using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Infrastructure.Parsers
{
    public class UserActivityParser : IForensicArtifactParser
    {
        public string ArtifactCategory => "Activitate Utilizator (Shellbags, LNK & JumpLists)";
        public string SupportedExtension => ".lnk";

        public bool CanParse(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return false;
            string name = Path.GetFileName(filePath).ToLowerInvariant();
            string ext = Path.GetExtension(filePath).ToLowerInvariant();
            return ext == ".lnk" || name.EndsWith(".automaticdestinations-ms") || name.EndsWith(".customdestinations-ms") || name.Contains("shellbags") || name.Contains("bagmru") || name.Contains("recent");
        }

        public async Task<List<ForensicArtifact>> ParseAsync(string filePath, string hostId, CancellationToken cancellationToken = default)
        {
            var results = new List<ForensicArtifact>();
            if (!File.Exists(filePath)) return results;

            await Task.Run(() =>
            {
                try
                {
                    byte[] data = File.ReadAllBytes(filePath);
                    if (data.Length < 76) return;

                    string sha256 = ComputeSha256(data);
                    string ext = Path.GetExtension(filePath).ToLowerInvariant();

                    // 1. Parsare fișiere LNK (Windows Shortcut: ShellLinkHeader MS-SHLLINK)
                    if (ext == ".lnk" || (data.Length >= 76 && BitConverter.ToUInt32(data, 0) == 0x0000004C))
                    {
                        // Header size = 0x4C (76 bytes)
                        // CLSID = 00021401-0000-0000-C000-000000000046
                        uint linkFlags = BitConverter.ToUInt32(data, 0x14);
                        long creationTimeFt = BitConverter.ToInt64(data, 0x1C);
                        long accessTimeFt = BitConverter.ToInt64(data, 0x24);
                        long writeTimeFt = BitConverter.ToInt64(data, 0x2C);
                        uint fileSize = BitConverter.ToUInt32(data, 0x34);

                        DateTime targetCreated = DateTime.UtcNow;
                        DateTime targetModified = DateTime.UtcNow;
                        if (creationTimeFt > 0) try { targetCreated = DateTime.FromFileTimeUtc(creationTimeFt); } catch { }
                        if (writeTimeFt > 0) try { targetModified = DateTime.FromFileTimeUtc(writeTimeFt); } catch { }

                        // Căutăm string-uri Unicode sau ASCII în structura LinkInfo / StringData
                        string targetPath = ExtractPathFromStringData(data) ?? Path.GetFileNameWithoutExtension(filePath);

                        results.Add(new ForensicArtifact
                        {
                            HostId = hostId,
                            ArtifactType = "LNK Shortcut Activity",
                            Name = Path.GetFileName(targetPath),
                            SourceFilePath = filePath,
                            SourceSha256 = sha256,
                            Timestamp = targetModified,
                            TimestampSemantics = TimeSemantics.LastExecution,
                            Strength = EvidenceStrength.ExecutionPossible,
                            Summary = $"Interacțiune LNK: Fișierul scurtătură indică deschiderea țintei [{targetPath}] ({fileSize / 1024:N0} KB). Data modificării țintei: {targetModified:yyyy-MM-dd HH:mm:ss} UTC.",
                            MitreTechniqueId = "T1204.002",
                            Properties = new Dictionary<string, string>
                            {
                                { "Cale Țintă LNK", targetPath },
                                { "Dimensiune Țintă (Bytes)", fileSize.ToString() },
                                { "Data Creare Țintă (UTC)", targetCreated.ToString("yyyy-MM-dd HH:mm:ss") },
                                { "Data Modificare Țintă (UTC)", targetModified.ToString("yyyy-MM-dd HH:mm:ss") },
                                { "Forță Probatorie", "Interacțiune Utilizator / Fișier Deschis Recent" }
                            }
                        });
                    }
                    // 2. JumpLists (AutomaticDestinations-ms / CustomDestinations-ms)
                    else if (filePath.Contains("Destinations-ms") || ext.Contains("destinations"))
                    {
                        var fileInfo = new FileInfo(filePath);
                        string appId = Path.GetFileNameWithoutExtension(filePath).Replace(".automaticDestinations", "").Replace(".customDestinations", "");

                        results.Add(new ForensicArtifact
                        {
                            HostId = hostId,
                            ArtifactType = "JumpList Activity",
                            Name = $"AppId: {appId}",
                            SourceFilePath = filePath,
                            SourceSha256 = sha256,
                            Timestamp = fileInfo.LastWriteTimeUtc,
                            TimestampSemantics = TimeSemantics.Recorded,
                            Strength = EvidenceStrength.ExecutionProven,
                            Summary = $"Container JumpList pentru aplicația [{appId}]. Înregistrează fișierele și folderele recent deschise din bara de activități (Taskbar MRU).",
                            MitreTechniqueId = "T1074.001",
                            Properties = new Dictionary<string, string>
                            {
                                { "Aplicație AppId", appId },
                                { "Dimensiune Container", $"{fileInfo.Length / 1024:N0} KB" },
                                { "Ultimul Acces JumpList", fileInfo.LastWriteTimeUtc.ToString("yyyy-MM-dd HH:mm:ss") }
                            }
                        });
                    }
                    // 3. Shellbags / generic
                    else
                    {
                        var fileInfo = new FileInfo(filePath);
                        results.Add(new ForensicArtifact
                        {
                            HostId = hostId,
                            ArtifactType = "Shellbags Explorer Navigation",
                            Name = Path.GetFileName(filePath),
                            SourceFilePath = filePath,
                            SourceSha256 = sha256,
                            Timestamp = fileInfo.LastWriteTimeUtc,
                            TimestampSemantics = TimeSemantics.Recorded,
                            Strength = EvidenceStrength.FileExistenceOnly,
                            Summary = $"Artefact de navigare foldere (Shellbags) cules de pe [{hostId}]. Permite identificarea folderelor explorate în mod interactiv de către utilizator.",
                            MitreTechniqueId = "T1083",
                            Properties = new Dictionary<string, string>
                            {
                                { "Sursă Fișier", filePath },
                                { "Tip Artefact", "Shellbag MRU Navigation Tree" }
                            }
                        });
                    }
                }
                catch { }
            }, cancellationToken);

            return results;
        }

        private static string? ExtractPathFromStringData(byte[] data)
        {
            try
            {
                // Căutare euristică pentru o cale de tip "C:\" sau "\\server\"
                for (int i = 76; i < data.Length - 6; i++)
                {
                    if (data[i] >= (byte)'A' && data[i] <= (byte)'Z' && data[i + 1] == (byte)':' && data[i + 2] == (byte)'\\')
                    {
                        // ASCII Path
                        int end = i;
                        while (end < data.Length && data[end] >= 32 && data[end] <= 126 && data[end] != 0)
                        {
                            end++;
                        }
                        if (end - i > 3)
                        {
                            return Encoding.ASCII.GetString(data, i, end - i);
                        }
                    }
                    else if (data[i] >= (byte)'A' && data[i] <= (byte)'Z' && data[i + 1] == 0 && data[i + 2] == (byte)':' && data[i + 3] == 0 && data[i + 4] == (byte)'\\' && data[i + 5] == 0)
                    {
                        // Unicode Path
                        int end = i;
                        while (end + 1 < data.Length && !(data[end] == 0 && data[end + 1] == 0))
                        {
                            end += 2;
                        }
                        if (end - i > 6)
                        {
                            return Encoding.Unicode.GetString(data, i, end - i);
                        }
                    }
                }
            }
            catch { }

            return null;
        }

        private static string ComputeSha256(byte[] data)
        {
            using var sha = SHA256.Create();
            return Convert.ToHexString(sha.ComputeHash(data)).ToLowerInvariant();
        }
    }
}
