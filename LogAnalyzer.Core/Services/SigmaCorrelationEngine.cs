using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class MultiEventCorrelationFinding
    {
        public string AttackScenario { get; set; } = string.Empty;
        public string Severity { get; set; } = "Critical";
        public string Description { get; set; } = string.Empty;
        public string MitreTechniqueId { get; set; } = "T1078";
        public TimeSpan TimeWindow { get; set; }
        public int InvolvedEventsCount { get; set; }
        public DateTime FirstEventUtc { get; set; }
        public DateTime LastEventUtc { get; set; }
        public string ContainmentActionRo { get; set; } = string.Empty;
    }

    public class SigmaCorrelationEngine
    {
        public List<MultiEventCorrelationFinding> CorrelateEvents(IEnumerable<ParsedEvent> events)
        {
            var findings = new List<MultiEventCorrelationFinding>();
            if (events == null) return findings;

            var ordered = events.OrderBy(e => e.TimeCreated).ToList();
            if (ordered.Count == 0) return findings;

            // Scenariul 1: Brute-Force urmat de Autentificare Reușită (EID 4625 -> EID 4624 în fereastră de 5 min)
            var failures = ordered.Where(e => e.EventId == 4625).ToList();
            var successes = ordered.Where(e => e.EventId == 4624).ToList();

            if (failures.Count >= 5 && successes.Count > 0)
            {
                var lastFail = failures.Last();
                var nextSuccess = successes.FirstOrDefault(s => s.TimeCreated >= lastFail.TimeCreated && (s.TimeCreated - lastFail.TimeCreated).TotalMinutes <= 5);

                if (nextSuccess != null)
                {
                    findings.Add(new MultiEventCorrelationFinding
                    {
                        AttackScenario = "Atac Brute-Force încununat de Succes (Credential Stuffing / Password Spray)",
                        Severity = "Critical",
                        Description = $"Identificate {failures.Count} eșecuri consecutive de autentificare (EID 4625) urmate de o autentificare cu succes (EID 4624) la {nextSuccess.TimeCreated:yyyy-MM-dd HH:mm:ss} UTC.",
                        MitreTechniqueId = "T1110.001 / T1078",
                        TimeWindow = nextSuccess.TimeCreated - failures.First().TimeCreated,
                        InvolvedEventsCount = failures.Count + 1,
                        FirstEventUtc = failures.First().TimeCreated,
                        LastEventUtc = nextSuccess.TimeCreated,
                        ContainmentActionRo = "1. Blocați imediat IP-ul sursă în firewall.\n2. Forțați resetarea parolei și revocarea sesiunii pentru utilizatorul autentificat.\n3. Activați autentificarea multi-factor (MFA)."
                    });
                }
            }

            // Scenariul 2: Ștergere Copii Shadow (vssadmin/wmic) urmată de Oprire Servicii (EID 7036 / EID 4688)
            var vssDeletes = ordered.Where(e => e.EventId == 4688 && (e.Message?.Contains("delete shadows", StringComparison.OrdinalIgnoreCase) == true || e.Message?.Contains("resize shadowstorage", StringComparison.OrdinalIgnoreCase) == true)).ToList();
            var serviceStops = ordered.Where(e => e.EventId == 7036 && e.Message?.Contains("stopped", StringComparison.OrdinalIgnoreCase) == true).ToList();

            if (vssDeletes.Count > 0)
            {
                findings.Add(new MultiEventCorrelationFinding
                {
                    AttackScenario = "Comportament Distructiv Pre-Ransomware (Inhibit System Recovery)",
                    Severity = "Critical",
                    Description = $"Detectată comanda de ștergere a copiilor Shadow Volume (VSS) prin [{vssDeletes.First().Message}]. Acest tipar precedă de regulă criptarea masivă a datelor de către ransomware.",
                    MitreTechniqueId = "T1490 / T1486",
                    TimeWindow = TimeSpan.FromMinutes(1),
                    InvolvedEventsCount = vssDeletes.Count + serviceStops.Count,
                    FirstEventUtc = vssDeletes.First().TimeCreated,
                    LastEventUtc = vssDeletes.Last().TimeCreated,
                    ContainmentActionRo = "1. Deconectați IMEDIAT stația de la orice conexiune de rețea (izolare fizică/logică).\n2. Opriți procesele părinte suspecte.\n3. Nu reporniți sistemul pentru a nu pierde cheile de criptare din memoria RAM."
                });
            }

            // Scenariul 3: Creare Serviciu Nou (EID 7045) în urma unei sesiuni de rețea (EID 4624 Type 3)
            var type3Logons = ordered.Where(e => e.EventId == 4624 && e.XmlData != null && e.XmlData.Contains("LogonType>3")).ToList();
            var serviceInstalls = ordered.Where(e => e.EventId == 7045).ToList();

            if (type3Logons.Count > 0 && serviceInstalls.Count > 0)
            {
                var match = serviceInstalls.FirstOrDefault(si => type3Logons.Any(t => Math.Abs((si.TimeCreated - t.TimeCreated).TotalSeconds) <= 60));
                if (match != null)
                {
                    findings.Add(new MultiEventCorrelationFinding
                    {
                        AttackScenario = "Mișcare Laterală prin Creare de Serviciu (PsExec / Lateral Movement)",
                        Severity = "High",
                        Description = $"Identificată autentificare de rețea (SMB/RPC Logon Type 3) urmată în mai puțin de 60 de secunde de instalarea unui nou serviciu Windows (EID 7045: {match.Message}).",
                        MitreTechniqueId = "T1021.002 / T1569.002",
                        TimeWindow = TimeSpan.FromSeconds(60),
                        InvolvedEventsCount = 2,
                        FirstEventUtc = match.TimeCreated.AddSeconds(-30),
                        LastEventUtc = match.TimeCreated,
                        ContainmentActionRo = "1. Inspectați binarul înregistrat ca serviciu și verificați semnătura digitală.\n2. Blocați traficul SMB (port 445) între stațiile de lucru din același VLAN.\n3. Verificați persistența în registru sub HKLM\\SYSTEM\\CurrentControlSet\\Services."
                    });
                }
            }

            return findings;
        }
    }
}
