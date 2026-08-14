using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class AnomalyDetectionEngine
    {
        private static readonly HashSet<string> KnownSystemProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "smss.exe",
            "wininit.exe", "winlogon.exe", "explorer.exe", "taskhostw.exe", "runtimebroker.exe"
        };

        private static readonly HashSet<string> LegitimateSystemPaths = new(StringComparer.OrdinalIgnoreCase)
        {
            @"C:\Windows\System32",
            @"C:\Windows\SysWOW64",
            @"C:\Windows",
            @"C:\Windows\SystemApps",
            @"C:\Windows\WinSxS"
        };

        /// <summary>
        /// Calculează entropia Shannon a unui șir de caractere.
        /// Valori peste 4.5 indică adesea payload-uri criptate, comprimate sau obfuscate (ex: Base64, RC4).
        /// </summary>
        public static double CalculateShannonEntropy(string? text)
        {
            if (string.IsNullOrEmpty(text)) return 0.0;

            var frequencies = new Dictionary<char, int>();
            foreach (char c in text)
            {
                if (frequencies.ContainsKey(c)) frequencies[c]++;
                else frequencies[c] = 1;
            }

            double entropy = 0.0;
            int length = text.Length;

            foreach (var kvp in frequencies)
            {
                double probability = (double)kvp.Value / length;
                entropy -= probability * Math.Log2(probability);
            }

            return entropy;
        }

        /// <summary>
        /// Detectează anomalii comportamentale în evenimentele analizate.
        /// </summary>
        public List<DetectedIssue> DetectAnomalies(IEnumerable<ParsedEvent> events)
        {
            var anomalies = new List<DetectedIssue>();

            var failedLogonsByUser = new Dictionary<string, List<ParsedEvent>>(StringComparer.OrdinalIgnoreCase);
            var successfulLogonsByUser = new Dictionary<string, List<ParsedEvent>>(StringComparer.OrdinalIgnoreCase);

            foreach (var ev in events)
            {
                // 1. Analiză Entropie pe Comenzi PowerShell / CMD / Scripturi (EID 4688, 4104, 20107)
                if (ev.EventId == 4688 || ev.EventId == 4104 || ev.EventId == 20107 || ev.EventId == 20109)
                {
                    string commandLine = ev.Message ?? string.Empty;
                    if (commandLine.Length > 60)
                    {
                        double entropy = CalculateShannonEntropy(commandLine);
                        if (entropy >= 4.8)
                        {
                            anomalies.Add(new DetectedIssue
                            {
                                Title = $"Comandă cu Entropie Extremă ({entropy:F2}) - Posibil Payload Criptat/Obfuscat",
                                Severity = "High",
                                Explanation = $"Comanda conține o densitate informațională anormală (Entropie: {entropy:F2} / 8.0). Tipar caracteristic pentru scripturi obfuscate, payload-uri Cobalt Strike, PowerShell Encoded sau shellcode injection.\n\nComandă: {Truncate(commandLine, 300)}",
                                ComplianceTag = "Heuristic Anomaly - Shannon Entropy",
                                MitreTechniqueId = "T1027",
                                MitreTacticName = "Defense Evasion",
                                Status = AlertStatus.Nouă,
                                RelatedEvents = new List<ParsedEvent> { ev }
                            });
                        }
                    }
                }

                // 2. Detecție Process Masquerading (Proces de sistem rulat dintr-un folder temporar)
                if (ev.EventId == 4688 || ev.EventId == 20107)
                {
                    string msg = ev.Message ?? string.Empty;
                    foreach (var sysProc in KnownSystemProcesses)
                    {
                        if (msg.Contains(sysProc, StringComparison.OrdinalIgnoreCase))
                        {
                            bool isSuspiciousLocation = msg.Contains(@"\Users\", StringComparison.OrdinalIgnoreCase) ||
                                                        msg.Contains(@"\Temp\", StringComparison.OrdinalIgnoreCase) ||
                                                        msg.Contains(@"\AppData\", StringComparison.OrdinalIgnoreCase) ||
                                                        msg.Contains(@"\Public\", StringComparison.OrdinalIgnoreCase) ||
                                                        msg.Contains(@"\ProgramData\", StringComparison.OrdinalIgnoreCase);

                            if (isSuspiciousLocation)
                            {
                                anomalies.Add(new DetectedIssue
                                {
                                    Title = $"Process Masquerading: {sysProc} lansat din cale suspectă",
                                    Severity = "Critical",
                                    Explanation = $"Procesul critic de sistem '{sysProc}' a fost executat dintr-o locație nelegitimă (Users/Temp/AppData), indicând un malware care se camuflează sub un nume legitim.\n\nDetalii: {Truncate(msg, 300)}",
                                    ComplianceTag = "MITRE ATT&CK - Masquerading",
                                    MitreTechniqueId = "T1036.005",
                                    MitreTacticName = "Defense Evasion",
                                    Status = AlertStatus.Nouă,
                                    RelatedEvents = new List<ParsedEvent> { ev }
                                });
                            }
                        }
                    }
                }

                // 3. Autentificări Nocturne Neobișnuite (Off-Hours Logon: 01:00 - 05:00)
                if (ev.EventId == 4624)
                {
                    var hour = ev.TimeCreated.Hour;
                    if (hour >= 1 && hour <= 4)
                    {
                        anomalies.Add(new DetectedIssue
                        {
                            Title = $"Autentificare Nocturnă Neobișnuită (Off-Hours: {ev.TimeCreated:HH:mm})",
                            Severity = "Medium",
                            Explanation = $"S-a înregistrat o autentificare cu succes în afara orelor standard de lucru ({ev.TimeCreated:HH:mm:ss}) pe gazda {ev.MachineName}. Poate indica un atacator ce operează dintr-un alt fus orar.",
                            ComplianceTag = "User Behavioral Anomaly",
                            MitreTechniqueId = "T1078",
                            MitreTacticName = "Initial Access",
                            Status = AlertStatus.Nouă,
                            RelatedEvents = new List<ParsedEvent> { ev }
                        });
                    }
                }
            }

            return anomalies;
        }

        private static string Truncate(string str, int maxLen)
        {
            if (string.IsNullOrEmpty(str)) return string.Empty;
            return str.Length <= maxLen ? str : str.Substring(0, maxLen) + "...";
        }
    }
}
