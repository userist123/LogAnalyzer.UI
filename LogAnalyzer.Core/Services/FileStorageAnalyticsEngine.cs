using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class StorageAuditItem
    {
        public string ResourcePath { get; set; } = string.Empty;
        public string RiskCategory { get; set; } = "Excessive Permissions"; // "Excessive Permissions", "Orphaned SID Owner", "Stale Unaccessed Data"
        public string Details { get; set; } = string.Empty;
        public string Severity { get; set; } = "Medium";
        public string StorageImpact { get; set; } = "Reclaimable / Security Risk";
        public DateTime LastAccessed { get; set; } = DateTime.UtcNow;
    }

    public class FileStorageAnalyticsEngine
    {
        public List<StorageAuditItem> AnalyzeStorageRisks(IEnumerable<ParsedEvent> events)
        {
            var items = new List<StorageAuditItem>();
            if (events == null) return items;

            var list = events.ToList();

            // 1. Detectare Permisiuni Deschise / ACL-uri Nereglementare (Everyone Full Control pe partajări)
            var shareAclEvents = list.Where(e => e.EventId == 5145 && e.Message != null && (e.Message.Contains("Everyone", StringComparison.OrdinalIgnoreCase) || e.Message.Contains("Anonymous", StringComparison.OrdinalIgnoreCase) || e.Message.Contains("0x1F01FF"))).ToList();
            if (shareAclEvents.Count > 0)
            {
                items.Add(new StorageAuditItem
                {
                    ResourcePath = @"\\FileServer\Public_Shares",
                    RiskCategory = "File Analysis: Permisiuni Deschise Excesive (Everyone / Anonymous Access)",
                    Details = $"Identificate {shareAclEvents.Count} accese cu permisiuni depline nesegregate (Everyone / Anonymous). Risc de divulgare de date confidențiale.",
                    Severity = "High",
                    StorageImpact = "Restricționare ACL Necesară",
                    LastAccessed = shareAclEvents.Max(s => s.TimeCreated)
                });
            }

            // 2. Detectare Obiecte cu Proprietar Necunoscut / Orphaned SIDs
            var orphanedEvents = list.Where(e => e.Message != null && e.Message.Contains("S-1-5-21-") && e.Message.Contains("Deleted Account", StringComparison.OrdinalIgnoreCase)).ToList();
            if (orphanedEvents.Count > 0)
            {
                items.Add(new StorageAuditItem
                {
                    ResourcePath = @"\\FileServer\UserData\OrphanedProfiles\",
                    RiskCategory = "File Analysis: Proprietar Orfan (Orphaned SID - Cont Șters)",
                    Details = "Identificate directoare și fișiere care aparțin unor SID-uri de utilizatori șterși din Active Directory. Necesită reatribuire ownership.",
                    Severity = "Medium",
                    StorageImpact = "Curățare & Reassign Owner",
                    LastAccessed = orphanedEvents.Max(o => o.TimeCreated)
                });
            }

            return items;
        }
    }
}
