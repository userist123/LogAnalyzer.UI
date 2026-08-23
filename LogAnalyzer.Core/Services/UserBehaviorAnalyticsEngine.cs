using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class UserBehaviorAnalyticsEngine
    {
        public List<UbaAnomalyItem> Evaluate(IEnumerable<ParsedEvent> events)
        {
            var anomalies = new List<UbaAnomalyItem>();
            if (events == null) return anomalies;

            var list = events.ToList();

            // 1. Detectare autentificare Ã®n afara orelor normale (23:00 - 06:00)
            var offHoursLogons = list.Where(e => e.EventId == 4624 && (e.TimeCreated.Hour >= 23 || e.TimeCreated.Hour < 6)).ToList();
            foreach (var e in offHoursLogons)
            {
                string user = ExtractUserFromMessage(e.Message);
                if (!string.IsNullOrEmpty(user) && !user.EndsWith("$"))
                {
                    anomalies.Add(new UbaAnomalyItem
                    {
                        Username = user,
                        AnomalyType = "Autentificare Ã®n Afara Orelor Normale (Off-Hours Logon)",
                        Severity = "High",
                        RiskWeight = 75.0,
                        Description = $"Utilizatorul {user} s-a autentificat la ora {e.TimeCreated:HH:mm:ss} pe staÈ›ia {e.MachineName}. Abatere comportamentalÄƒ de la programul de lucru autorizat.",
                        Timestamp = e.TimeCreated
                    });
                }
            }

            // 2. Detectare sesiuni concurente pe mai multe staÈ›ii Ã®n interval scurt
            var logonsByUser = list.Where(e => e.EventId == 4624).GroupBy(e => ExtractUserFromMessage(e.Message)).Where(g => !string.IsNullOrEmpty(g.Key) && !g.Key.EndsWith("$"));

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
                            AnomalyType = "Sesiuni Concurente Multi-StaÈ›ie (Impossible Concurrent Logon)",
                            Severity = "Critical",
                            RiskWeight = 90.0,
                            Description = $"Utilizatorul {userGroup.Key} s-a autentificat simultan pe {e1.MachineName} È™i {e2.MachineName} Ã®ntr-un interval de {Math.Round((e2.TimeCreated - e1.TimeCreated).TotalMinutes, 1)} minute.",
                            Timestamp = e2.TimeCreated
                        });
                    }
                }
            }

            // 3. Detectare rafalÄƒ de autentificÄƒri eÈ™uate urmate de succes imediat (Brute-Force Compromise)
            var failedLogons = list.Where(e => e.EventId == 4625).ToList();
            var successLogons = list.Where(e => e.EventId == 4624).ToList();

            foreach (var userGroup in failedLogons.GroupBy(e => ExtractUserFromMessage(e.Message)).Where(g => !string.IsNullOrEmpty(g.Key) && !g.Key.EndsWith("$")))
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
                            AnomalyType = "Succes dupÄƒ RafalÄƒ EÈ™uatÄƒ (Brute-Force Compromise)",
                            Severity = "Critical",
                            RiskWeight = 95.0,
                            Description = $"Contul {userGroup.Key} a Ã®nregistrat {userGroup.Count()} eÈ™ecuri consecutive urmate de o autentificare reuÈ™itÄƒ la {subsequentSuccess.TimeCreated:HH:mm:ss}.",
                            Timestamp = subsequentSuccess.TimeCreated
                        });
                    }
                }
            }

            return anomalies;
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
                        if (!string.IsNullOrEmpty(user) && !user.Equals("-") && !user.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase))
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
