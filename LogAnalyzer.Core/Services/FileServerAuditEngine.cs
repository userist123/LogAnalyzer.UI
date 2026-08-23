using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class FileServerAuditEngine
    {
        public List<FileServerAuditFinding> Analyze(IEnumerable<ParsedEvent> events)
        {
            var findings = new List<FileServerAuditFinding>();
            if (events == null) return findings;

            var list = events.ToList();

            var fileEvents = list.Where(e => e.EventId == 4663 || e.EventId == 4660 || e.EventId == 5145).ToList();

            var massModifications = fileEvents.Where(e => e.Message != null && (e.Message.Contains(".locked") || e.Message.Contains(".crypto") || e.Message.Contains("0x10000") || e.Message.Contains("WriteData"))).ToList();
            if (massModifications.Count >= 5)
            {
                findings.Add(new FileServerAuditFinding
                {
                    ActivityType = "File Audit: Model Criptare MasivÄƒ FiÈ™iere (Ransomware Behavior)",
                    SharePathOrFileName = @"\\FileServer\DataShare\",
                    AccessedBy = "Compromised User Session",
                    Severity = "Critical",
                    ServerHost = "FileServer",
                    MitreTechniqueId = "T1486",
                    Description = $"DetectatÄƒ o rafalÄƒ de {massModifications.Count} operaÈ›iuni de scriere/modificare rapidÄƒ pe partajarea de fiÈ™iere. SemnÄƒtura corespunde unui atac activ de tip Ransomware (T1486 Data Encrypted for Impact).",
                    RemediationActionRo = "1. OpriÈ›i imediat serviciul Server (LanmanServer) pe staÈ›ia de fiÈ™iere pentru a bloca propagarea.\n2. IzolaÈ›i adresa IP a staÈ›iei client care a emis cererile de scriere SMB.\n3. IniÈ›ializaÈ›i restaurarea din snapshot VSS / backup imutabil offline.",
                    Timestamp = massModifications.Max(m => m.TimeCreated)
                });
            }

            var sensitiveAccess = fileEvents.Where(e => e.Message != null && (e.Message.Contains("confidential", StringComparison.OrdinalIgnoreCase) || e.Message.Contains("salarii", StringComparison.OrdinalIgnoreCase) || e.Message.Contains("passwords", StringComparison.OrdinalIgnoreCase) || e.Message.Contains("backup", StringComparison.OrdinalIgnoreCase))).ToList();
            if (sensitiveAccess.Count > 0)
            {
                findings.Add(new FileServerAuditFinding
                {
                    ActivityType = "File Audit: Acces NeobiÈ™nuit pe Directoare ConfidenÈ›iale / FinanÈ›e",
                    SharePathOrFileName = @"\\FileServer\Confidential\",
                    AccessedBy = "Audited User",
                    Severity = "High",
                    ServerHost = "FileServer",
                    MitreTechniqueId = "T1039",
                    Description = $"ÃŽnregistrat acces pe directoare marcate ca avÃ¢nd nivel ridicat de confidenÈ›ialitate ({sensitiveAccess.Count} evenimente). Risc de colectare neautorizatÄƒ de date È™i exfiltrare.",
                    RemediationActionRo = "1. VerificaÈ›i dacÄƒ utilizatorul are autorizaÈ›ie scrisÄƒ 'Need-to-Know' pentru dosarul accesat.\n2. AuditaÈ›i dacÄƒ s-au copiat volume mari de date prin analiza jurnalului de trafic reÈ›ea.",
                    Timestamp = sensitiveAccess.Max(s => s.TimeCreated)
                });
            }

            return findings;
        }
    }
}
