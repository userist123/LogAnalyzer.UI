using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class UserBehaviorAnalyticsEngine
    {
        private static readonly HashSet<string> IgnoredSystemAccounts = new(StringComparer.OrdinalIgnoreCase)
        {
            "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "ANONYMOUS LOGON",
            "DWM-1", "DWM-2", "DWM-3", "UMFD-0", "UMFD-1", "UMFD-2"
        };

        public List<UbaAnomalyItem> Evaluate(IEnumerable<ParsedEvent> events)
        {
            var anomalies = new List<UbaAnomalyItem>();
            if (events == null) return anomalies;

            var list = events.ToList();

            // 1. Detectare autentificare în afara orelor normale (23:00 - 06:00) - Agregat per Utilizator
            var offHoursLogons = list.Where(e => e.EventId == 4624 && (e.TimeCreated.Hour >= 23 || e.TimeCreated.Hour < 6)).ToList();
            var validOffHours = offHoursLogons.Where(e => IsRealUser(ExtractUserFromMessage(e.Message))).GroupBy(e => ExtractUserFromMessage(e.Message));

            foreach (var g in validOffHours)
            {
                var first = g.Min(e => e.TimeCreated);
                var last = g.Max(e => e.TimeCreated);
                anomalies.Add(new UbaAnomalyItem
                {
                    Username = g.Key,
                    Workstation = g.FirstOrDefault()?.MachineName ?? "Workstation",
                    AnomalyType = "Autentificare în Afara Orelor Normale (Off-Hours Logon)",
                    Severity = "High",
                    RiskWeight = 75.0,
                    Description = $"Utilizatorul {g.Key} a înregistrat {g.Count()} autentificări nocturne între {first:HH:mm} și {last:HH:mm}. Abatere comportamentală de la programul autorizat.",
                    Timestamp = last
                });
            }

            // 2. Detectare sesiuni concurente pe mai multe stații în interval scurt
            var logonsByUser = list.Where(e => e.EventId == 4624)
                .GroupBy(e => ExtractUserFromMessage(e.Message))
                .Where(g => IsRealUser(g.Key));

            foreach (var userGroup in logonsByUser)
            {
                var userEvents = userGroup.OrderBy(e => e.TimeCreated).ToList();
                for (int i = 0; i < userEvents.Count - 1; i++)
                {
                    var e1 = userEvents[i];
                    var e2 = userEvents[i + 1];
                    if (!string.Equals(e1.MachineName, e2.MachineName, StringComparison.OrdinalIgnoreCase) &&
                        (e2.TimeCreated - e1.TimeCreated).TotalMinutes < 15)
                    {
                        anomalies.Add(new UbaAnomalyItem
                        {
                            Username = userGroup.Key,
                            Workstation = $"{e1.MachineName}, {e2.MachineName}",
                            AnomalyType = "Sesiuni Concurente Multi-Stație (Impossible Concurrent Logon)",
                            Severity = "Critical",
                            RiskWeight = 90.0,
                            Description = $"Utilizatorul {userGroup.Key} s-a autentificat simultan pe {e1.MachineName} și {e2.MachineName} într-un interval de {Math.Round((e2.TimeCreated - e1.TimeCreated).TotalMinutes, 1)} minute.",
                            Timestamp = e2.TimeCreated
                        });
                        break; // Un singur semnal UBA per utilizator pentru a evita spamul
                    }
                }
            }

            // 3. Detectare rafală de autentificări eșuate urmate de succes imediat (Brute-Force Compromise)
            var failedLogons = list.Where(e => e.EventId == 4625).ToList();
            var successLogons = list.Where(e => e.EventId == 4624).ToList();

            foreach (var userGroup in failedLogons.GroupBy(e => ExtractUserFromMessage(e.Message)).Where(g => IsRealUser(g.Key)))
            {
                if (userGroup.Count() >= 3)
                {
                    var lastFail = userGroup.Max(e => e.TimeCreated);
                    var subsequentSuccess = successLogons.FirstOrDefault(s => ExtractUserFromMessage(s.Message) == userGroup.Key && s.TimeCreated >= lastFail && (s.TimeCreated - lastFail).TotalMinutes <= 5);

                    if (subsequentSuccess != null)
                    {
                        anomalies.Add(new UbaAnomalyItem
                        {
                            Username = userGroup.Key,
                            Workstation = subsequentSuccess.MachineName ?? "Workstation",
                            AnomalyType = "Succes după Rafală Eșuată (Brute-Force Compromise)",
                            Severity = "Critical",
                            RiskWeight = 95.0,
                            Description = $"Contul {userGroup.Key} a înregistrat {userGroup.Count()} eșecuri consecutive urmate de o autentificare reușită la {subsequentSuccess.TimeCreated:HH:mm:ss}.",
                            Timestamp = subsequentSuccess.TimeCreated
                        });
                    }
                }
            }

            return anomalies;
        }

        private static bool IsRealUser(string? user)
        {
            if (string.IsNullOrEmpty(user) || user.Equals("-")) return false;
            if (user.EndsWith("$") || IgnoredSystemAccounts.Contains(user)) return false;
            return true;
        }

        private static string ExtractUserFromMessage(string? message)
        {
            if (string.IsNullOrEmpty(message)) return string.Empty;
            var lines = message.Split('\n');
            foreach (var line in lines)
            {
                if (line.Contains("TargetUserName:", StringComparison.OrdinalIgnoreCase) || line.Contains("Account Name:", StringComparison.OrdinalIgnoreCase))
                {
                    var parts = line.Split(':');
                    if (parts.Length > 1)
                    {
                        var user = parts[1].Trim();
                        if (!string.IsNullOrEmpty(user) && !user.Equals("-"))
                        {
                            return user;
                        }
                    }
                }
            }
            return string.Empty;
        }
    }
}
