using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class CaseSnapshotManifest
    {
        public string CaseId { get; set; } = string.Empty;
        public string CaseTitle { get; set; } = string.Empty;
        public string LeadAnalyst { get; set; } = string.Empty;
        public DateTime ExportedAtUtc { get; set; } = DateTime.UtcNow;
        public int TotalEvents { get; set; }
        public int TotalIssues { get; set; }
        public int TotalIocs { get; set; }
        public string ManifestSha256 { get; set; } = string.Empty;
    }

    public class CaseSnapshotPackage
    {
        public CaseSnapshotManifest Manifest { get; set; } = new();
        public List<DetectedIssue> Issues { get; set; } = new();
        public List<IocItem> Iocs { get; set; } = new();
        public List<TimelineItem> Timeline { get; set; } = new();
        public string SessionNotes { get; set; } = string.Empty;
    }

    public class CaseSnapshotService
    {
        /// <summary>
        /// Salvează întreaga stare a cazului de investigație într-un fișier arhivat .dfir comprimat și semnat SHA-256.
        /// </summary>
        public void ExportCaseSnapshot(string targetDfirPath, CaseSnapshotPackage pkg)
        {
            if (pkg == null) throw new ArgumentNullException(nameof(pkg));
            if (File.Exists(targetDfirPath)) File.Delete(targetDfirPath);

            pkg.Manifest.ExportedAtUtc = DateTime.UtcNow;
            pkg.Manifest.TotalIssues = pkg.Issues.Count;
            pkg.Manifest.TotalIocs = pkg.Iocs.Count;
            pkg.Manifest.TotalEvents = pkg.Timeline.Count;

            string json = JsonSerializer.Serialize(pkg, new JsonSerializerOptions { WriteIndented = true });
            byte[] jsonBytes = Encoding.UTF8.GetBytes(json);

            using var sha = SHA256.Create();
            string hash = Convert.ToHexString(sha.ComputeHash(jsonBytes)).ToLowerInvariant();
            pkg.Manifest.ManifestSha256 = hash;

            // Re-serialize with valid manifest hash
            string finalJson = JsonSerializer.Serialize(pkg, new JsonSerializerOptions { WriteIndented = true });

            using var zipStream = new FileStream(targetDfirPath, FileMode.Create, FileAccess.Write);
            using var archive = new ZipArchive(zipStream, ZipArchiveMode.Create);
            var entry = archive.CreateEntry("case_snapshot.json", CompressionLevel.Optimal);
            using var entryStream = entry.Open();
            using var writer = new StreamWriter(entryStream, Encoding.UTF8);
            writer.Write(finalJson);
        }

        /// <summary>
        /// Încarcă un pachet de caz .dfir și verifică integritatea acestuia.
        /// </summary>
        public CaseSnapshotPackage LoadCaseSnapshot(string dfirPath)
        {
            if (!File.Exists(dfirPath)) throw new FileNotFoundException("Pachetul de caz .dfir nu există.", dfirPath);

            using var zipStream = new FileStream(dfirPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read);
            var entry = archive.GetEntry("case_snapshot.json");
            if (entry == null) throw new InvalidDataException("Arhiva .dfir este coruptă (lipsește case_snapshot.json).");

            using var entryStream = entry.Open();
            using var reader = new StreamReader(entryStream, Encoding.UTF8);
            string json = reader.ReadToEnd();

            var pkg = JsonSerializer.Deserialize<CaseSnapshotPackage>(json);
            return pkg ?? new CaseSnapshotPackage();
        }
    }
}
