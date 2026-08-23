using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class LolbasFinding
    {
        public string BinaryName { get; set; } = string.Empty;
        public string Category { get; set; } = "LOLBAS Execution"; // ex: "Download", "Execute", "Bypass", "Parent-Child Anomaly"
        public string Severity { get; set; } = "High";
        public string CommandLine { get; set; } = string.Empty;
        public string ParentProcess { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string MitreTechniqueId { get; set; } = "T1218";
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    }

    public class LolbasEngine
    {
        private static readonly Dictionary<string, (string Category, string Mitre, string Desc)> _knownLolbas = new(StringComparer.OrdinalIgnoreCase)
        {
            { "certutil.exe", ("Download / Decode", "T1105 / T1140", "Utilitarul certutil este folosit frecvent pentru descărcarea de payload-uri (-urlcache -split -f) sau decodarea fișierelor Base64 (-decode).") },
            { "bitsadmin.exe", ("Download / Persistence", "T1197", "Serviciul BITS este utilizat pentru descărcarea asincronă de malware și persistență stealth.") },
            { "mshta.exe", ("Execution / Bypass", "T1218.005", "Execută scripturi HTA/VBScript/JScript direct din memorie sau de la URL-uri externe, ocolind controalele de binar.") },
            { "rundll32.exe", ("Execution", "T1218.011", "Încarcă și execută biblioteci DLL arbitrare sau funcții exportate nesigure.") },
            { "regsvr32.exe", ("Bypass / Proxy Execution", "T1218.010", "Tehnica Squiblydoo: încarcă scripturi COM (.sct) de la distanță prin scrobj.dll fără a atinge discul.") },
            { "wmic.exe", ("Execution / Recon", "T1047", "Utilizat pentru interogarea sistemului sau lansarea de procese la distanță ('process call create').") },
            { "cscript.exe", ("Scripting", "T1059.005", "Motor de execuție VBScript/JScript utilizat în etapele inițiale de infecție.") },
            { "wscript.exe", ("Scripting", "T1059.005", "Lansator GUI de scripturi Windows Script Host.") },
            { "installutil.exe", ("Bypass AppLocker", "T1218.004", "Compilator .NET utilizat pentru executarea codului nesemnat prin ocolirea politicilor de securitate.") }
        };

        private static readonly string[] _suspiciousParents = new[] { "w3wp.exe", "sqlservr.exe", "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "httpd.exe", "nginx.exe" };

        public List<LolbasFinding> Analyze(IEnumerable<ParsedEvent> events)
        {
            var results = new List<LolbasFinding>();
            if (events == null) return results;

            foreach (var ev in events)
            {
                if (ev.EventId != 4688 && ev.EventId != 1) continue;

                string msg = ev.Message?.ToLowerInvariant() ?? string.Empty;
                string xml = ev.XmlData ?? string.Empty;

                // 1. Verificare Binare LOLBAS
                foreach (var kvp in _knownLolbas)
                {
                    if (msg.Contains(kvp.Key.ToLowerInvariant()))
                    {
                        bool isHighRisk = msg.Contains("-urlcache") || msg.Contains("-decode") || msg.Contains("http") || msg.Contains("javascript:") || msg.Contains("vbscript:") || msg.Contains("scrobj.dll");

                        results.Add(new LolbasFinding
                        {
                            BinaryName = kvp.Key,
                            Category = kvp.Value.Category,
                            Severity = isHighRisk ? "Critical" : "High",
                            CommandLine = ev.Message ?? string.Empty,
                            Description = kvp.Value.Desc,
                            MitreTechniqueId = kvp.Value.Mitre,
                            Timestamp = ev.TimeCreated
                        });
                        break;
                    }
                }

                // 2. Verificare Relații Anomale Părinte-Copil (Web Shell / Office Exploit)
                foreach (var parent in _suspiciousParents)
                {
                    if (msg.Contains(parent) && (msg.Contains("cmd.exe") || msg.Contains("powershell.exe") || msg.Contains("pwsh.exe") || msg.Contains("whoami.exe")))
                    {
                        results.Add(new LolbasFinding
                        {
                            BinaryName = "Proces Shell Spawnat de Serviciu/Office",
                            Category = "Anomalie Relație Părinte-Copil",
                            Severity = "Critical",
                            ParentProcess = parent,
                            CommandLine = ev.Message ?? string.Empty,
                            Description = $"ALERTA GRAVĂ: Procesul [{parent}] (Server Web sau Document Office) a lansat o consolă de comandă. Tipar clasic de Web Shell (T1505.003) sau exploatare prin document malițios (T1204.002).",
                            MitreTechniqueId = "T1505.003",
                            Timestamp = ev.TimeCreated
                        });
                        break;
                    }
                }
            }

            return results;
        }
    }
}
