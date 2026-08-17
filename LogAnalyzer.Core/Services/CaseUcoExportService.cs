using System;
using System.Collections.Generic;
using System.Text.Json;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class CaseUcoExportService
    {
        public string ExportCaseJsonLd(
            string caseId,
            string investigatorName,
            string organization,
            IEnumerable<ForensicArtifact> artifacts,
            IEnumerable<ProvenanceLedgerEntry> provenanceLedger)
        {
            var root = new Dictionary<string, object>
            {
                { "@context", new Dictionary<string, string>
                    {
                        { "case", "https://ontology.caseontology.org/case/investigation#" },
                        { "uco-core", "https://ontology.unifiedcyberontology.org/uco/core#" },
                        { "uco-observable", "https://ontology.unifiedcyberontology.org/uco/observable#" },
                        { "uco-identity", "https://ontology.unifiedcyberontology.org/uco/identity#" },
                        { "xsd", "http://www.w3.org/2001/XMLSchema#" }
                    }
                },
                { "@id", $"case:investigation-{caseId}" },
                { "@type", "case:Investigation" },
                { "case:name", $"DFIR Investigation Case #{caseId}" },
                { "case:focus", "Digital Forensics & Evidence Preservation" },
                { "case:leadInvestigator", investigatorName },
                { "case:organization", organization },
                { "uco-core:createdTime", DateTime.UtcNow.ToString("O") },
                { "@graph", BuildGraphObjects(artifacts, provenanceLedger) }
            };

            return JsonSerializer.Serialize(root, new JsonSerializerOptions { WriteIndented = true });
        }

        private List<Dictionary<string, object>> BuildGraphObjects(
            IEnumerable<ForensicArtifact> artifacts,
            IEnumerable<ProvenanceLedgerEntry> ledger)
        {
            var graph = new List<Dictionary<string, object>>();

            if (artifacts != null)
            {
                foreach (var art in artifacts)
                {
                    graph.Add(new Dictionary<string, object>
                    {
                        { "@id", $"case:artifact-{art.Id}" },
                        { "@type", "uco-observable:ObservableObject" },
                        { "uco-core:name", art.Name },
                        { "uco-observable:filePath", art.SourceFilePath },
                        { "uco-observable:hash", new Dictionary<string, string> { { "SHA-256", art.SourceSha256 } } },
                        { "uco-core:description", art.Summary },
                        { "case:evidenceStrength", art.Strength.ToString() },
                        { "case:timeSemantics", art.TimestampSemantics.ToString() },
                        { "uco-core:timestamp", art.Timestamp.ToString("O") }
                    });
                }
            }

            if (ledger != null)
            {
                foreach (var entry in ledger)
                {
                    graph.Add(new Dictionary<string, object>
                    {
                        { "@id", $"case:provenance-entry-{entry.SequenceNumber}" },
                        { "@type", "case:ProvenanceRecord" },
                        { "case:actionType", entry.ActionType },
                        { "case:evidenceRef", entry.EvidenceReference },
                        { "case:sourceSha256", entry.SourceSha256 },
                        { "case:entryHash", entry.EntryHash },
                        { "case:previousHash", entry.PreviousEntryHash },
                        { "uco-core:timestamp", entry.TimestampUtc.ToString("O") }
                    });
                }
            }

            return graph;
        }
    }
}
