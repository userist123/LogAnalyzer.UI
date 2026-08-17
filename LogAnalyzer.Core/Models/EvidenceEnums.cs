using System;
using System.Collections.Generic;

namespace LogAnalyzer.Core.Models
{
    public enum EvidenceStrength
    {
        ExecutionProven,    // Prefetch, Amcache, UserAssist, BAM/DAM (Execuție Certă)
        ExecutionPossible,  // Shimcache Win10/11, LNK (Execuție probabilă/posibilă)
        FileExistenceOnly,  // MFT, USN Journal (Doar existență fișier pe disc)
        ConfigurationOnly,  // Setări registru, Politici, Servicii
        ContextOnly         // Evenimente informative conexe
    }

    public enum TimeSemantics
    {
        Created,            // Data creării fișierului/obiectului
        Recorded,           // Data înregistrării în log/jurnal
        LastExecution,      // Data ultimei rulări
        BatchFlushed,       // Data sincronizării în calup (ex: SRUM, Registry)
        Modified,           // Data ultimei modificări
        Inferred            // Timestamp dedus/estimat
    }

    public class ForensicArtifact
    {
        public string Id { get; set; } = Guid.NewGuid().ToString();
        public string HostId { get; set; } = "LocalHost";
        public string ArtifactType { get; set; } = string.Empty; // ex: "Prefetch", "Amcache", "MFT", "BAM", "SRUM", "Browser"
        public string Name { get; set; } = string.Empty;
        public string SourceFilePath { get; set; } = string.Empty;
        public long SourceOffset { get; set; } = 0;
        public string SourceSha256 { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public TimeSemantics TimestampSemantics { get; set; } = TimeSemantics.Recorded;
        public EvidenceStrength Strength { get; set; } = EvidenceStrength.ContextOnly;
        public string Summary { get; set; } = string.Empty;
        public string MitreTechniqueId { get; set; } = string.Empty;
        public Dictionary<string, string> Properties { get; set; } = new();
    }
}
