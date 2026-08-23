using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class UbaAnomalyItem
    {
        public string Username { get; set; } = string.Empty;
        public string AnomalyType { get; set; } = string.Empty; // "Off-Hours Logon", "Concurrent Workstations", "Brute-Force Followed by Success", "Anomalous RDP Access"
        public string Severity { get; set; } = "High";
        public string Description { get; set; } = string.Empty;
        public string SourceIp { get; set; } = string.Empty;
        public string Workstation { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public double RiskWeight { get; set; } = 75.0;
    }

    public class UserBehaviorAnalyticsEngine
    {
        public List<UbaAnomalyItem> Evaluate(IEnumerable<ParsedEvent> events)
        {
            var anomalies = new List<UbaAnomalyItem>();
            if (events == null) return anomalies;

            var list = events.ToList();

            // 1. Logon în afara programului de lucru (23:00 - 05:30)
            var offHours = list.Where(e => (e.EventId == 4624 || e.EventId == 4768) && (e.TimeCreated.Hour >= 23 || e.TimeCreated.Hour < 6)).ToList();
            var groupedOffHours = offHours.GroupBy(e => ExtractUser(e)).Where(g => !string.IsNullOrEmpty(g.Key) && !g.Key.EndsWith("$") && !g.Key.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase));

            foreach (var g in groupedOffHours)
            {
                var sample = g.First();
                anomalies.Add(new UbaAnomalyItem
                {
                    Username = g.Key,
                    AnomalyType = "UBA: Autentificare în Afara Orelor Normale de Lucru",
                    Severity = "Medium",
                    Description = $"Utilizatorul '{g.Key}' s-a autentificat de {g.Count()} ori în intervalul orar 23:00 - 06:00. Necesită validare dacă activitatea corespunde unei ture de noapte autorizate sau unui acces neautorizat.",
                    SourceIp = sample.MachineName ?? "Rețea Internă",
                    Workstation = sample.MachineName ?? "Unknown",
                    Timestamp = g.Max(e => e.TimeCreated),
                    RiskWeight = 45.0
                });
            }

            // 2. Sesiuni concurente pe mai multe stații în interval de sub 15 minute
            var successfulLogons = list.Where(e => e.EventId == 4624).OrderBy(e => e.TimeCreated).ToList();
            var userLogons = successfulLogons.GroupBy(e => ExtractUser(e)).Where(g => !string.IsNullOrEmpty(g.Key) && !g.Key.EndsWith("$") && !g.Key.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase));

            foreach (var userGroup in userLogons)
            {
                var stations = userGroup.Select(e => e.MachineName).Where(m => !string.IsNullOrEmpty(m)).Distinct().ToList();
                if (stations.Count >= 2)
                {
                    var times = userGroup.Select(e => e.TimeCreated).ToList();
                    var minTime = times.Min();
                    var maxTime = times.Max();
                    if ((maxTime - minTime).TotalMinutes < 15)
                    {
                        anomalies.Add(new UbaAnomalyItem
                        {
                            Username = userGroup.Key,
                            AnomalyType = "UBA: Sesiuni Concurente Multi-Stație (Lateral Movement / Credential Sharing)",
                            Severity = "High",
                            Description = $"Contul '{userGroup.Key}' a deschis sesiuni simultane pe {stations.Count} stații diferite ({string.Join(", ", stations)}) în mai puțin de 15 minute.",
                            SourceIp = string.Join(", ", stations),
                            Workstation = stations.FirstOrDefault() ?? "Multiple",
                            Timestamp = maxTime,
                            RiskWeight = 80.0
                        });
                    }
                }
            }

            // 3. Eșecuri repetate urmate de succes imediat (Brute-Force / Password Guessing Success)
            var failedLogons = list.Where(e => e.EventId == 4625 || e.EventId == 4771).ToList();
            var failedUsers = failedLogons.GroupBy(e => ExtractUser(e)).Where(g => g.Count() >= 3 && !string.IsNullOrEmpty(g.Key));

            foreach (var fGroup in failedUsers)
            {
                var user = fGroup.Key;
                var hasSubsequentSuccess = successfulLogons.Any(s => ExtractUser(s).Equals(user, StringComparison.OrdinalIgnoreCase) && s.TimeCreated >= fGroup.Min(f => f.TimeCreated));
                if (hasSubsequentSuccess)
                {
                    anomalies.Add(new UbaAnomalyItem
                    {
                        Username = user,
                        AnomalyType = "UBA: Succes Autentificare După Tentative Eșuate Multiple (Brute-Force Compromise)",
                        Severity = "Critical",
                        Description = $"Contul '{user}' a înregistrat {fGroup.Count()} autentificări eșuate urmate de o autentificare reușită. Risc critic de compromitere a credențialelor prin atac de ghicire/forță brută.",
                        SourceIp = fGroup.First().MachineName ?? "Rețea",
                        Workstation = fGroup.First().MachineName ?? "Workstation",
                        Timestamp = fGroup.Max(f => f.TimeCreated),
                        RiskWeight = 95.0
                    });
                }
            }

            return anomalies;
        }

        private static string ExtractUser(ParsedEvent e)
        {
            if (e.Message != null)
            {
                var lines = e.Message.Split('\n');
                foreach (var line in lines)
                {
                    if (line.Contains("Account Name:", StringComparison.OrdinalIgnoreCase) || line.Contains("TargetUserName:", StringComparison.OrdinalIgnoreCase))
                    {
                        var parts = line.Split(':');
                        if (parts.Length > 1)
                        {
                            var u = parts[1].Trim();
                            if (!string.IsNullOrEmpty(u) && !u.Equals("-") && !u.EndsWith("$")) return u;
                        }
                    }
                }
            }

            if (e.XmlData != null && e.XmlData.Contains("TargetUserName\">"))
            {
                int start = e.XmlData.IndexOf("TargetUserName\">") + 16;
                int end = e.XmlData.IndexOf("<", start);
                if (start > 15 && end > start)
                {
                    var u = e.XmlData.Substring(start, end - start).Trim();
                    if (!string.IsNullOrEmpty(u) && !u.Equals("-") && !u.EndsWith("$")) return u;
                }
            }

            return string.Empty;
        }
    }
}
