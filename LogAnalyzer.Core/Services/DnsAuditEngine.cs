using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class DnsAuditEngine
    {
        public List<DnsAuditFinding> Analyze(IEnumerable<ParsedEvent> events)
        {
            var findings = new List<DnsAuditFinding>();
            if (events == null) return findings;

            var list = events.ToList();

            var dnsEvents = list.Where(e => (e.ProviderName != null && e.ProviderName.Contains("DNS-Server", StringComparison.OrdinalIgnoreCase)) ||
                                            (e.EventId >= 257 && e.EventId <= 260) ||
                                            (e.EventId == 5136 && e.Message != null && e.Message.Contains("DC=DomainDnsZones", StringComparison.OrdinalIgnoreCase))).ToList();

            foreach (var e in dnsEvents)
            {
                string msg = e.Message ?? string.Empty;
                string findingType = "DNS: Modificare ZonÄƒ / ÃŽnregistrare";
                string severity = "Medium";
                string record = "Unknown.Record";
                string zone = "domain.local";
                string actionRo = "InspectaÈ›i legitimitatea modificÄƒrii DNS Ã®n consola DNS Manager.";

                if (e.EventId == 257 || e.EventId == 258)
                {
                    findingType = "DNS: Creare / Modificare ÃŽnregistrare ResursÄƒ";
                    severity = "Medium";
                    actionRo = "1. VerificaÈ›i adresa IP asociatÄƒ Ã®nregistrÄƒrii DNS.\n2. ConfirmaÈ›i dacÄƒ modificarea a fost efectuatÄƒ de un administrator autorizat.";
                }
                else if (e.EventId == 259)
                {
                    findingType = "DNS: È˜tergere ÃŽnregistrare ResursÄƒ";
                    severity = "High";
                    actionRo = "VerificaÈ›i dacÄƒ È™tergerea cauzeazÄƒ Ã®ntreruperea serviciilor de rezoluÈ›ie (Denial of Service).";
                }
                else if (e.EventId == 5136 && msg.Contains("DomainDnsZones", StringComparison.OrdinalIgnoreCase))
                {
                    findingType = "DNS: Alterare Obiect Active Directory DNS (DNS Poisoning Risk)";
                    severity = "Critical";
                    actionRo = "1. AuditaÈ›i ACL-urile pe containerul CN=MicrosoftDNS,DC=DomainDnsZones.\n2. AsiguraÈ›i-vÄƒ cÄƒ nu s-au acordat drepturi de creare Ã®nregistrÄƒri pentru 'Authenticated Users'.";
                }

                findings.Add(new DnsAuditFinding
                {
                    FindingType = findingType,
                    RecordName = record,
                    ZoneName = zone,
                    Severity = severity,
                    MitreTechniqueId = "T1071.004",
                    Description = $"ÃŽnregistrat eveniment DNS Server EID {e.EventId}: {msg}",
                    RemediationActionRo = actionRo,
                    Timestamp = e.TimeCreated
                });
            }

            return findings;
        }
    }
}
