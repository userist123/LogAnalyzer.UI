using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class KerberosAdFinding
    {
        public string AttackType { get; set; } = string.Empty; // ex: "Kerberoasting", "AS-REP Roasting", "Pass-the-Hash", "DCSync"
        public string Severity { get; set; } = "Critical";
        public string Description { get; set; } = string.Empty;
        public string TargetAccount { get; set; } = string.Empty;
        public string ClientIp { get; set; } = string.Empty;
        public string MitreTechniqueId { get; set; } = string.Empty;
        public string ContainmentActionRo { get; set; } = string.Empty;
        public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    }

    public class KerberosAdAttackEngine
    {
        public List<KerberosAdFinding> AnalyzeEvents(IEnumerable<ParsedEvent> events)
        {
            var findings = new List<KerberosAdFinding>();
            if (events == null) return findings;

            var eventList = events.ToList();

            // 1. Detecție Kerberoasting (EID 4769 - Cereri de TGS cu criptare slabă RC4 0x17)
            var tgsRequests = eventList.Where(e => e.EventId == 4769).ToList();
            var rc4Requests = tgsRequests.Where(e => 
                (e.XmlData != null && (e.XmlData.Contains("0x17") || e.XmlData.Contains("TicketEncryptionType>0x17"))) ||
                (e.Message != null && e.Message.Contains("0x17"))
            ).ToList();

            if (rc4Requests.Count >= 3)
            {
                findings.Add(new KerberosAdFinding
                {
                    AttackType = "Kerberoasting (TGS Request Burst cu RC4-HMAC)",
                    Severity = "Critical",
                    Description = $"Detectat un volum de {rc4Requests.Count} cereri de tichete de serviciu Kerberos TGS folosind cifru slab RC4 (0x17). Atacatorii extrag tichete de serviciu pentru a le sparge offline (hash cracking).",
                    TargetAccount = "Multiple Service Accounts",
                    ClientIp = "Rețea Internă",
                    MitreTechniqueId = "T1558.003",
                    ContainmentActionRo = "1. Schimbați parolele conturilor de serviciu (SPN) vizate.\n2. Forțați criptarea AES-256 pentru toate conturile de serviciu (msDS-SupportedEncryptionTypes).\n3. Rotiți parola contului krbtgt de două ori.",
                    DetectedAt = rc4Requests.Max(r => r.TimeCreated)
                });
            }

            // 2. Detecție AS-REP Roasting (EID 4768 / 4771 - Pre-autentificare Kerberos lipsă sau eșuată)
            var asRepEvents = eventList.Where(e => e.EventId == 4768 || e.EventId == 4771).ToList();
            var noPreAuth = asRepEvents.Where(e => 
                (e.Message != null && e.Message.Contains("Pre-authentication failed")) ||
                (e.XmlData != null && e.XmlData.Contains("0x18"))
            ).ToList();

            if (noPreAuth.Count > 0)
            {
                findings.Add(new KerberosAdFinding
                {
                    AttackType = "AS-REP Roasting (Kerberos Pre-Authentication Disabled)",
                    Severity = "High",
                    Description = $"Identificate cereri de autentificare Kerberos AS-REQ fără pre-autentificare obligatorie (DONT_REQ_PREAUTH). Permite obținerea unui hash TGT ce poate fi spart offline fără a interacționa cu Domain Controller-ul.",
                    TargetAccount = "Cont cu Pre-Auth dezactivat",
                    ClientIp = "Rețea Locală",
                    MitreTechniqueId = "T1558.004",
                    ContainmentActionRo = "1. Reactivați bifa 'Do not require Kerberos preauthentication' pe toate conturile de utilizator.\n2. Auditați conturile afectate pentru a vedea dacă au fost create recent.",
                    DetectedAt = noPreAuth.Max(r => r.TimeCreated)
                });
            }

            // 3. Detecție Pass-the-Hash / Overpass-the-Hash (EID 4624 Tip 9 NewCredentials)
            var type9Logons = eventList.Where(e => e.EventId == 4624 && e.XmlData != null && e.XmlData.Contains("LogonType>9")).ToList();
            if (type9Logons.Count > 0)
            {
                findings.Add(new KerberosAdFinding
                {
                    AttackType = "Pass-the-Hash / Overpass-the-Hash (Logon Type 9)",
                    Severity = "High",
                    Description = $"Detectate {type9Logons.Count} sesiuni de tip LogonType 9 (NewCredentials). Acest tipar este specific execuției 'runas /netonly' sau uneltelor Mimikatz sekurlsa::pth pentru a injecta hash-uri NTLM în memoria LSASS.",
                    TargetAccount = "Cont Privilegiat",
                    ClientIp = "Localhost",
                    MitreTechniqueId = "T1550.002",
                    ContainmentActionRo = "1. Adăugați administratorii în grupul 'Protected Users'.\n2. Activați funcționalitatea Windows Defender Credential Guard.\n3. Blocați NTLM în rețea în favoarea Kerberos exclusiv.",
                    DetectedAt = type9Logons.Max(r => r.TimeCreated)
                });
            }

            return findings;
        }
    }
}
