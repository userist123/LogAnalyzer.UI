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
    public class UsbForensicsParser : IForensicArtifactParser
    {
        public string ArtifactCategory => "Control Dispozitive & USB Forensics (P16-P18)";
        public string SupportedExtension => ".log";

        public bool CanParse(string filePath)
        {
            if (string.IsNullOrWhiteSpace(filePath)) return false;
            string name = Path.GetFileName(filePath).ToLowerInvariant();
            return name.Contains("setupapi") || name.Contains("usbstor") || name.Contains("usb") || name.Contains("mounteddevices") || name.EndsWith(".reg") || name.EndsWith(".log");
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
                    var fileInfo = new FileInfo(filePath);

                    if (fileName.Contains("setupapi"))
                    {
                        var lines = File.ReadAllLines(filePath);
                        var usbRegex = new Regex(@"USBSTOR\\Disk&Ven_([^&]+)&Prod_([^&]+)&Rev_([^\\]+)\\([^\s\]\r\n]+)", RegexOptions.IgnoreCase | RegexOptions.Compiled);
                        int count = 0;

                        foreach (var line in lines)
                        {
                            var match = usbRegex.Match(line);
                            if (match.Success)
                            {
                                string vendor = match.Groups[1].Value;
                                string prod = match.Groups[2].Value;
                                string serial = match.Groups[4].Value;

                                results.Add(new ForensicArtifact
                                {
                                    HostId = hostId,
                                    ArtifactType = "Dispozitiv USB Conectat (setupapi.dev.log)",
                                    Name = $"{vendor} {prod} (S/N: {serial})",
                                    SourceFilePath = filePath,
                                    SourceSha256 = sha256,
                                    Timestamp = fileInfo.LastWriteTimeUtc,
                                    TimestampSemantics = TimeSemantics.Recorded,
                                    Strength = EvidenceStrength.ExecutionProven,
                                    Summary = $"[USB FORENSICS P16-P18] Identificat mediu de stocare extern '{vendor} {prod}', Număr Serie Fizic Imutabil: '{serial}' conectat pe hostul [{hostId}].",
                                    MitreTechniqueId = "T1091",
                                    Properties = new Dictionary<string, string>
                                    {
                                        { "Producător (Vendor)", vendor },
                                        { "Produs (Product)", prod },
                                        { "Hardware Serial Number (P16)", serial },
                                        { "Sursă Jurnal", "setupapi.dev.log" },
                                        { "Conformitate Invariante", "P16 (Imutabilitate Telemetrie Hardware) & P18 (Lanț de Custodie)" },
                                        { "Forță Probatorie", "Execuție Certă / Probă Fizică Hardware" }
                                    }
                                });
                                count++;
                                if (count >= 25) break;
                            }
                        }
                    }
                    else
                    {
                        results.Add(new ForensicArtifact
                        {
                            HostId = hostId,
                            ArtifactType = "USB Registry Key Hive",
                            Name = Path.GetFileName(filePath),
                            SourceFilePath = filePath,
                            SourceSha256 = sha256,
                            Timestamp = fileInfo.LastWriteTimeUtc,
                            TimestampSemantics = TimeSemantics.Recorded,
                            Strength = EvidenceStrength.ExecutionProven,
                            Summary = $"Artefact USBSTOR / MountedDevices colectat de pe [{hostId}] pentru auditul dispozitivelor externe.",
                            MitreTechniqueId = "T1091",
                            Properties = new Dictionary<string, string>
                            {
                                { "Sursă Fișier", filePath },
                                { "Invariante Impuse", "P16-P18" }
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
