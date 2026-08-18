using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class RansomwareFinding
    {
        public string ActivityType { get; set; } = string.Empty; // ex: "Shadow Copy Deletion", "Inhibit System Recovery", "Mass File Renaming"
        public string Severity { get; set; } = "Critical";
        public string CommandOrProcess { get; set; } = string.Empty;
        public string MitreTechniqueId { get; set; } = "T1490";
        public string Description { get; set; } = string.Empty;
        public string RecommendedMitigationRo { get; set; } = string.Empty;
        public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    }

    public class RansomwareDetectionEngine
    {
        private static readonly string[] DestructiveCommands = new[]
        {
            "vssadmin delete shadows",
            "vssadmin.exe delete shadows",
            "wmic shadowcopy delete",
            "wbadmin delete catalog",
            "wbadmin delete systemstatebackup",
            "bcdedit /set {default} recoveryenabled no",
            "bcdedit /set {default} bootstatuspolicy ignoreallfailures",
            "bcdedit.exe /set {default} recoveryenabled no",
            "wevtutil cl security",
            "wevtutil cl system",
            "net stop vss",
            "net stop swprv",
            "net stop sql",
            "sc config vss start= disabled"
        };

        private static readonly string[] RansomwareExtensions = new[]
        {
            ".lockbit", ".blackcat", ".akira", ".alphv", ".medusa", ".royal", ".enc", ".locked", ".crypto"
        };

        /// <summary>
        /// Detectează comportamente și comenzi premergătoare sau specifice atacurilor de tip Ransomware.
        /// </summary>
        public List<RansomwareFinding> AnalyzeEvents(IEnumerable<ParsedEvent> events)
        {
            var findings = new List<RansomwareFinding>();
            if (events == null) return findings;

            foreach (var ev in events)
            {
                string msg = ev.Message ?? string.Empty;
                string lowerMsg = msg.ToLowerInvariant();

                // 1. Detecție comenzi destructive VSS / BCDEDIT (T1490)
                foreach (var cmd in DestructiveCommands)
                {
                    if (lowerMsg.Contains(cmd))
                    {
                        findings.Add(new RansomwareFinding
                        {
                            ActivityType = "Inhibare Recuperare Sistem / Ștergere Copii de Siguranță (Shadow Copies)",
                            Severity = "Critical",
                            CommandOrProcess = cmd,
                            MitreTechniqueId = "T1490",
                            Description = $"Detectată execuția comenzii distructive '{cmd}' (EID {ev.EventId}) pe hostul [{ev.MachineName}]. Comportament tipic premergător criptării masive cu Ransomware.",
                            RecommendedMitigationRo = "1. Izolați imediat stația de la rețea (deconectare cablu / blocare port switch).\n2. Opriți procesul părinte și salvați un dump de memorie RAM.\n3. Verificați starea backup-urilor offline (air-gapped).",
                            DetectedAt = ev.TimeCreated
                        });
                        break;
                    }
                }

                // 2. Detecție extensii suspecte sau note de răscumpărare în mesaje
                if (ev.EventId == 4663 || ev.EventId == 11 || ev.EventId == 15) // File creation / modification
                {
                    foreach (var ext in RansomwareExtensions)
                    {
                        if (lowerMsg.Contains(ext))
                        {
                            findings.Add(new RansomwareFinding
                            {
                                ActivityType = "Scriere Fișiere cu Extensie Criptată Ransomware",
                                Severity = "Critical",
                                CommandOrProcess = ext,
                                MitreTechniqueId = "T1486",
                                Description = $"Detectată scrierea de fișiere cu extensia specifică de ransomware '{ext}' în evenimentul {ev.EventId}.",
                                RecommendedMitigationRo = "Declanșați playbook-ul de izolare totală și opriți serviciile SMB pe serverele de fișiere.",
                                DetectedAt = ev.TimeCreated
                            });
                            break;
                        }
                    }
                }
            }

            return findings;
        }
    }
}
