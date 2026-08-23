using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class DnsAuditFinding
    {
        public string FindingType { get; set; } = string.Empty; // "Rogue DNS Record", "DNS Zone Tampering", "DNS Poisoning / Redirection"
        public string Severity { get; set; } = "High";
        public string RecordName { get; set; } = string.Empty;
        public string RecordValue { get; set; } = string.Empty;
        public string ZoneName { get; set; } = string.Empty;
        public string MitreTechniqueId { get; set; } = "T1071.004";
        public string Description { get; set; } = string.Empty;
        public string RemediationActionRo { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }

    public class DnsAuditEngine
    {
        public List<DnsAuditFinding> Analyze(IEnumerable<ParsedEvent> events)
        {
            var findings = new List<DnsAuditFinding>();
            if (events == null) return findings;

            var list = events.ToList();

            // 1. Modificare Înregistrare DNS pe Domain Controller / Server DNS (EID 258 sau EID 5136 pe MicrosoftDNS)
            var modifiedRecords = list.Where(e => (e.EventId == 258 || e.EventId == 257) || (e.EventId == 5136 && e.Message != null && e.Message.Contains("MicrosoftDNS", StringComparison.OrdinalIgnoreCase))).ToList();
            if (modifiedRecords.Count > 0)
            {
                findings.Add(new DnsAuditFinding
                {
                    FindingType = "ADAudit DNS: Creare / Modificare Înregistrare DNS în Zona de Domeniu",
                    Severity = "High",
                    RecordName = "Domain DNS Record",
                    ZoneName = "Active Directory Integrated Zone",
                    MitreTechniqueId = "T1071.004",
                    Description = $"Detectate {modifiedRecords.Count} operațiuni de creare sau modificare înregistrări DNS (EID {string.Join(", ", modifiedRecords.Select(m => m.EventId).Distinct())}). Modificările neautorizate pot redirecționa traficul de autentificare către servere C2 malițioase.",
                    RemediationActionRo = "1. Auditați contul de utilizator care a efectuat modificarea DNS.\n2. Verificați adresa IP țintă a înregistrării în baza de Threat Intelligence.\n3. Revocați înregistrarea dacă nu există tichet aprobat.",
                    Timestamp = modifiedRecords.Max(m => m.TimeCreated)
                });
            }

            // 2. Ștergere Zonă sau Înregistrare DNS Critică (EID 259 / EID 260)
            var deletedRecords = list.Where(e => e.EventId == 259 || e.EventId == 260).ToList();
            if (deletedRecords.Count > 0)
            {
                findings.Add(new DnsAuditFinding
                {
                    FindingType = "ADAudit DNS: Ștergere Înregistrare sau Alterare Configurare Zonă DNS",
                    Severity = "High",
                    RecordName = "DNS Configuration Object",
                    ZoneName = "DomainDNSZones",
                    MitreTechniqueId = "T1489",
                    Description = $"Detectată ștergerea de înregistrări DNS sau reconfigurarea zonelor de rezoluție (EID {string.Join(", ", deletedRecords.Select(d => d.EventId).Distinct())}). Poate cauza Denial of Service asupra serviciilor de domeniu.",
                    RemediationActionRo = "1. Restaurați înregistrările DNS din backup-ul integrat Active Directory.\n2. Activați opțiunea 'Prevent accidental deletion' pe obiectele DNS.",
                    Timestamp = deletedRecords.Max(d => d.TimeCreated)
                });
            }

            return findings;
        }
    }
}
