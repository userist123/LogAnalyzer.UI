using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class EmployeeActivityAuditEngine
    {
        public List<EmployeeSessionActivity> AnalyzeWorkHours(IEnumerable<ParsedEvent> events)
        {
            var activities = new List<EmployeeSessionActivity>();
            if (events == null) return activities;

            var list = events.ToList();

            var sessionEvents = list.Where(e => e.EventId == 4624 || e.EventId == 4634 || e.EventId == 4800 || e.EventId == 4801).OrderBy(e => e.TimeCreated).ToList();

            var userGroups = sessionEvents.GroupBy(e => ExtractUser(e)).Where(g => !string.IsNullOrEmpty(g.Key) && !g.Key.EndsWith("$") && !g.Key.Equals("SYSTEM", StringComparison.OrdinalIgnoreCase));

            foreach (var ug in userGroups)
            {
                var userEvents = ug.ToList();
                var logons = userEvents.Where(e => e.EventId == 4624).ToList();
                var logoffs = userEvents.Where(e => e.EventId == 4634).ToList();
                int locks = userEvents.Count(e => e.EventId == 4800);
                int unlocks = userEvents.Count(e => e.EventId == 4801);

                DateTime firstLogon = logons.Count > 0 ? logons.Min(l => l.TimeCreated) : userEvents.Min(e => e.TimeCreated);
                DateTime? lastLogoff = logoffs.Count > 0 ? logoffs.Max(l => l.TimeCreated) : null;
                DateTime endTime = lastLogoff ?? userEvents.Max(e => e.TimeCreated);

                double totalHours = Math.Max(0.1, (endTime - firstLogon).TotalHours);
                if (totalHours > 24) totalHours = 8.0;

                activities.Add(new EmployeeSessionActivity
                {
                    Username = ug.Key,
                    Workstation = userEvents.FirstOrDefault()?.MachineName ?? "Workstation",
                    LogonTime = firstLogon,
                    LogoffTime = lastLogoff,
                    ActiveHours = Math.Round(totalHours, 2),
                    LockCount = locks,
                    UnlockCount = unlocks,
                    SessionStatus = lastLogoff.HasValue ? "Closed" : (locks > unlocks ? "Locked" : "Active")
                });
            }

            return activities;
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
            return string.Empty;
        }
    }
}
