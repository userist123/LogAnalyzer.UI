using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class FileStorageAnalyticsEngine
    {
        public List<StorageAuditItem> AnalyzeStorageRisks(IEnumerable<ParsedEvent> events)
        {
            var items = new List<StorageAuditItem>();
            if (events == null) return items;

            var list = events.ToList();

            var shareAclEvents = list.Where(e => e.EventId == 5145 && e.Message != null && (e.Message.Contains("Everyone", StringComparison.OrdinalIgnoreCase) || e.Message.Contains("Anonymous", StringComparison.OrdinalIgnoreCase) || e.Message.Contains("0x1F01FF"))).ToList();
            if (shareAclEvents.Count > 0)
            {
                items.Add(new StorageAuditItem
                {
                    ResourcePath = @"\\FileServer\Public_Shares",
                    RiskCategory = "File Analysis: Permisiuni Deschise Excesive (Everyone / Anonymous Access)",
                    Details = $"Identificate {shareAclEvents.Count} accese cu permisiuni depline nesegregate (Everyone / Anonymous). Risc de divulgare de date confidenÈ›iale.",
                    Severity = "High",
                    StorageImpact = "RestricÈ›ionare ACL NecesarÄƒ",
                    LastAccessed = shareAclEvents.Max(s => s.TimeCreated)
                });
            }

            var orphanedEvents = list.Where(e => e.Message != null && e.Message.Contains("S-1-5-21-") && e.Message.Contains("Deleted Account", StringComparison.OrdinalIgnoreCase)).ToList();
            if (orphanedEvents.Count > 0)
            {
                items.Add(new StorageAuditItem
                {
                    ResourcePath = @"\\FileServer\UserData\OrphanedProfiles\",
                    RiskCategory = "File Analysis: Proprietar Orfan (Orphaned SID - Cont È˜ters)",
                    Details = "Identificate directoare È™i fiÈ™iere care aparÈ›in unor SID-uri de utilizatori È™terÈ™i din Active Directory. NecesitÄƒ reatribuire ownership.",
                    Severity = "Medium",
                    StorageImpact = "CurÄƒÈ›are & Reassign Owner",
                    LastAccessed = orphanedEvents.Max(o => o.TimeCreated)
                });
            }

            return items;
        }
    }
}
