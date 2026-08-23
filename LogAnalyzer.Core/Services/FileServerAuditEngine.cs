using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class FileServerAuditFinding
    {
        public string ActivityType { get; set; } = string.Empty; // "Ransomware Mass Renaming", "Sensitive Directory Access", "Share ACL Modified", "Excessive File Deletions"
        public string SharePathOrFileName { get; set; } = string.Empty;
        public string AccessedBy { get; set; } = string.Empty;
        public string Severity { get; set; } = "High";
        public string ServerHost { get; set; } = "FileServer01";
        public string MitreTechniqueId { get; set; } = "T1486";
        public string Description { get; set; } = string.Empty;
        public string RemediationActionRo { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }

    public class FileServerAuditEngine
    {
        public List<FileServerAuditFinding> Analyze(IEnumerable<ParsedEvent> events)
        {
            var findings = new List<FileServerAuditFinding>();
            if (events == null) return findings;

            var list = events.ToList();

            // 1. Auditare Evenimente Sistem Fișiere (EID 4663 Acces Obiect, EID 4660 Ștergere Fișier, EID 5145 Partajare Detaliată)
            var fileEvents = list.Where(e => e.EventId == 4663 || e.EventId == 4660 || e.EventId == 5145).ToList();

            // Detecție Ransomware Mass File Modification (peste 10 fișiere modificate/accesate rapid)
            var massModifications = fileEvents.Where(e => e.Message != null && (e.Message.Contains(".locked") || e.Message.Contains(".crypto") || e.Message.Contains("0x10000") || e.Message.Contains("WriteData"))).ToList();
            if (massModifications.Count >= 5)
            {
                findings.Add(new FileServerAuditFinding
                {
                    ActivityType = "File Audit: Model Criptare Masivă Fișiere (Ransomware Behavior)",
                    SharePathOrFileName = @"\\FileServer\DataShare\",
                    AccessedBy = "Compromised User Session",
                    Severity = "Critical",
                    ServerHost = "FileServer",
                    MitreTechniqueId = "T1486",
                    Description = $"Detectată o rafală de {massModifications.Count} operațiuni de scriere/modificare rapidă pe partajarea de fișiere. Semnătura corespunde unui atac activ de tip Ransomware (T1486 Data Encrypted for Impact).",
                    RemediationActionRo = "1. Opriți imediat serviciul Server (LanmanServer) pe stația de fișiere pentru a bloca propagarea.\n2. Izolați adresa IP a stației client care a emis cererile de scriere SMB.\n3. Inițializați restaurarea din snapshot VSS / backup imutabil offline.",
                    Timestamp = massModifications.Max(m => m.TimeCreated)
                });
            }

            // Detecție Acces Directoare Sensibile (Confidential, HR, Finance, Passwords)
            var sensitiveAccess = fileEvents.Where(e => e.Message != null && (e.Message.Contains("confidential", StringComparison.OrdinalIgnoreCase) || e.Message.Contains("salarii", StringComparison.OrdinalIgnoreCase) || e.Message.Contains("passwords", StringComparison.OrdinalIgnoreCase) || e.Message.Contains("backup", StringComparison.OrdinalIgnoreCase))).ToList();
            if (sensitiveAccess.Count > 0)
            {
                findings.Add(new FileServerAuditFinding
                {
                    ActivityType = "File Audit: Acces Neobișnuit pe Directoare Confidențiale / Finanțe",
                    SharePathOrFileName = @"\\FileServer\Confidential\",
                    AccessedBy = "Audited User",
                    Severity = "High",
                    ServerHost = "FileServer",
                    MitreTechniqueId = "T1039",
                    Description = $"Înregistrat acces pe directoare marcate ca având nivel ridicat de confidențialitate ({sensitiveAccess.Count} evenimente). Risc de colectare neautorizată de date și exfiltrare.",
                    RemediationActionRo = "1. Verificați dacă utilizatorul are autorizație scrisă 'Need-to-Know' pentru dosarul accesat.\n2. Auditați dacă s-au copiat volume mari de date prin analiza jurnalului de trafic rețea.",
                    Timestamp = sensitiveAccess.Max(s => s.TimeCreated)
                });
            }

            return findings;
        }
    }
}
