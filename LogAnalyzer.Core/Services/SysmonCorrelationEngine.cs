using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class SysmonFinding
    {
        public string DetectionType { get; set; } = string.Empty; // ex: "Masquerading (OriginalFileName Mismatch)", "LSASS Memory Access", "DLL Hijacking", "Remote Thread Injection"
        public string Severity { get; set; } = "High";
        public int SysmonEventId { get; set; }
        public string ProcessName { get; set; } = string.Empty;
        public string TargetOrDetails { get; set; } = string.Empty;
        public string MitreTechniqueId { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    }

    public class SysmonCorrelationEngine
    {
        /// <summary>
        /// Analizează jurnalele Microsoft-Windows-Sysmon/Operational pentru a identifica tehnici avansate de evaziune și atac.
        /// </summary>
        public List<SysmonFinding> AnalyzeSysmonEvents(IEnumerable<ParsedEvent> events)
        {
            var findings = new List<SysmonFinding>();
            if (events == null) return findings;

            foreach (var ev in events)
            {
                string msg = ev.Message ?? string.Empty;
                string xml = ev.XmlData ?? string.Empty;
                string lowerMsg = msg.ToLowerInvariant();

                // 1. Sysmon EID 1: Masquerading (OriginalFileName mismatch, ex: cmd.exe renamed to svchost.exe)
                if (ev.EventId == 1)
                {
                    if (lowerMsg.Contains("svchost.exe") && (lowerMsg.Contains("powershell") || lowerMsg.Contains("cmd.exe") || lowerMsg.Contains("originalfilename: cmd.exe")))
                    {
                        findings.Add(new SysmonFinding
                        {
                            DetectionType = "Mascare Proces (Masquerading / OriginalFileName Mismatch)",
                            Severity = "Critical",
                            SysmonEventId = 1,
                            ProcessName = "svchost.exe (Fake)",
                            TargetOrDetails = "OriginalFileName: cmd.exe / powershell.exe",
                            MitreTechniqueId = "T1036.003",
                            Description = $"Detectată redenumirea unui interpretor de comenzi pentru a imita procesul de sistem 'svchost.exe'.",
                            DetectedAt = ev.TimeCreated
                        });
                    }
                }

                // 2. Sysmon EID 8: CreateRemoteThread (Process Injection)
                if (ev.EventId == 8 || lowerMsg.Contains("createremotethread") || lowerMsg.Contains("sourcetechnique: createremotethread"))
                {
                    findings.Add(new SysmonFinding
                    {
                        DetectionType = "Injecție de Cod în Proces la Distanță (CreateRemoteThread)",
                        Severity = "Critical",
                        SysmonEventId = 8,
                        ProcessName = "Source Process Injection",
                        TargetOrDetails = "Target Image Process",
                        MitreTechniqueId = "T1055.002",
                        Description = $"Detectată crearea unui fir de execuție la distanță (CreateRemoteThread) dintr-un proces nesigur într-un proces gazdă legitim.",
                        DetectedAt = ev.TimeCreated
                    });
                }

                // 3. Sysmon EID 10: ProcessAccess pe LSASS (GrantedAccess 0x1010 / 0x1fffff)
                if (ev.EventId == 10 && lowerMsg.Contains("lsass.exe"))
                {
                    bool isSuspiciousAccess = lowerMsg.Contains("0x1010") || lowerMsg.Contains("0x1fffff") || lowerMsg.Contains("0x1410") || lowerMsg.Contains("0x143a");
                    if (isSuspiciousAccess)
                    {
                        findings.Add(new SysmonFinding
                        {
                            DetectionType = "Tentativă Extragere Credențiale LSASS (ProcessAccess Scraping)",
                            Severity = "Critical",
                            SysmonEventId = 10,
                            ProcessName = "LSASS Scraper",
                            TargetOrDetails = "C:\\Windows\\System32\\lsass.exe",
                            MitreTechniqueId = "T1003.001",
                            Description = $"Detectat acces cu drepturi extinse (PROCESS_VM_READ / PROCESS_ALL_ACCESS) asupra procesului LSASS pentru extragerea de hash-uri/parole din memorie.",
                            DetectedAt = ev.TimeCreated
                        });
                    }
                }

                // 4. Sysmon EID 7: DLL Hijacking / ImageLoaded din Temp sau AppData
                if (ev.EventId == 7 && (lowerMsg.Contains("\\appdata\\local\\temp\\") || lowerMsg.Contains("\\users\\public\\")))
                {
                    findings.Add(new SysmonFinding
                    {
                        DetectionType = "Încărcare Modul Suspect / DLL Hijacking",
                        Severity = "High",
                        SysmonEventId = 7,
                        ProcessName = "ImageLoaded Engine",
                        TargetOrDetails = "DLL din folder Temp/Public",
                        MitreTechniqueId = "T1574.001",
                        Description = $"Detectată încărcarea unei biblioteci DLL dintr-un director cu permisiuni de scriere pentru utilizatori fără drepturi administrative (Temp/Public).",
                        DetectedAt = ev.TimeCreated
                    });
                }
            }

            return findings;
        }
    }
}
