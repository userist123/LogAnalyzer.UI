using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class KerberosAdFinding
    {
        public string AttackType { get; set; } = string.Empty; // ex: "Kerberoasting", "Privileged Group Modification", "Account Lockout", "DCSync", "Golden Ticket"
        public string Category { get; set; } = "Active Directory Security"; // "Authentication", "User Management", "Group Membership", "GPO Policy", "Exploit"
        public string Severity { get; set; } = "Critical";
        public string Description { get; set; } = string.Empty;
        public string TargetAccount { get; set; } = string.Empty;
        public string ClientIp { get; set; } = string.Empty;
        public string MitreTechniqueId { get; set; } = string.Empty;
        public string ContainmentActionRo { get; set; } = string.Empty;
        public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    }

    public class AdAuditSummary
    {
        public int TotalAdEventsAnalyzed { get; set; }
        public int UserAccountsCreated { get; set; }
        public int UserAccountsModified { get; set; }
        public int UserAccountsDeleted { get; set; }
        public int PasswordResets { get; set; }
        public int AccountLockouts { get; set; }
        public int PrivilegedGroupChanges { get; set; }
        public int GpoPolicyChanges { get; set; }
        public int KerberosAttacksDetected { get; set; }
    }

    public class KerberosAdAttackEngine
    {
        public AdAuditSummary GetAuditSummary(IEnumerable<ParsedEvent> events)
        {
            var summary = new AdAuditSummary();
            if (events == null) return summary;

            var list = events.ToList();
            summary.TotalAdEventsAnalyzed = list.Count(e => (e.EventId >= 4720 && e.EventId <= 4799) || e.EventId == 4662 || e.EventId == 4672 || e.EventId == 5136 || e.EventId == 5137 || e.EventId == 5141);
            summary.UserAccountsCreated = list.Count(e => e.EventId == 4720);
            summary.UserAccountsModified = list.Count(e => e.EventId == 4738 || e.EventId == 4722);
            summary.UserAccountsDeleted = list.Count(e => e.EventId == 4726);
            summary.PasswordResets = list.Count(e => e.EventId == 4724);
            summary.AccountLockouts = list.Count(e => e.EventId == 4740);
            summary.PrivilegedGroupChanges = list.Count(e => e.EventId == 4728 || e.EventId == 4732 || e.EventId == 4756);
            summary.GpoPolicyChanges = list.Count(e => e.EventId == 4739 || e.EventId == 5136 || e.EventId == 5137 || e.EventId == 5141);
            
            var findings = AnalyzeEvents(list);
            summary.KerberosAttacksDetected = findings.Count;
            return summary;
        }

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

            if (rc4Requests.Count >= 2)
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
                (e.Message != null && (e.Message.Contains("Pre-authentication failed") || e.Message.Contains("Pre-Auth Type: 0") || e.Message.Contains("Pre-Authentication Type: 0"))) ||
                (e.XmlData != null && (e.XmlData.Contains("0x18") || e.XmlData.Contains("PreAuthType>0<")))
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
            var type9Logons = eventList.Where(e => e.EventId == 4624 && ((e.XmlData != null && e.XmlData.Contains("LogonType>9")) || (e.Message != null && e.Message.Contains("Logon Type:\t\t9")))).ToList();
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

            // 4. Detecție DCSync (EID 4662 pe GUID-urile de replicare Active Directory)
            // DS-Replication-Get-Changes: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
            // DS-Replication-Get-Changes-All: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
            var dcSyncEvents = eventList.Where(e => e.EventId == 4662 && e.Message != null && 
                (e.Message.Contains("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", StringComparison.OrdinalIgnoreCase) || 
                 e.Message.Contains("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", StringComparison.OrdinalIgnoreCase) ||
                 (e.XmlData != null && (e.XmlData.Contains("1131f6aa") || e.XmlData.Contains("1131f6ad"))))).ToList();

            if (dcSyncEvents.Count > 0)
            {
                findings.Add(new KerberosAdFinding
                {
                    AttackType = "DCSync Attack (Extragere Hash-uri Active Directory)",
                    Severity = "Critical",
                    Description = $"Detectată o tentativă de replicare directă a bazei de date Active Directory (DS-Replication) de la un cont non-DC. Tehnica DCSync permite atacatorilor să ceară hash-ul parolei oricărui utilizator (inclusiv KRBTGT și Administrator) imitând un Domain Controller legitim.",
                    TargetAccount = "Domain Controller NTDS.dit",
                    ClientIp = "Cont Replicare Neautorizat",
                    MitreTechniqueId = "T1003.006",
                    ContainmentActionRo = "1. Izolați imediat stația sursă de la care s-a emis cererea de replicare.\n2. Revocați drepturile de 'Replicating Directory Changes' pentru toate conturile non-DC.\n3. Rotiți de urgență parola contului krbtgt de două ori la interval de 24 de ore.",
                    DetectedAt = dcSyncEvents.Max(r => r.TimeCreated)
                });
            }

            // 5. Detecție Golden Ticket / Privilegiu Special Nelimitat (EID 4672)
            var specialPrivLogons = eventList.Where(e => e.EventId == 4672 && e.Message != null && e.Message.Contains("SeEnableDelegationPrivilege")).ToList();
            if (specialPrivLogons.Count > 0)
            {
                findings.Add(new KerberosAdFinding
                {
                    AttackType = "Golden Ticket / Delegare Neregulamentară",
                    Severity = "Critical",
                    Description = $"Autentificare cu privilegii de delegare de sistem (SeEnableDelegationPrivilege) fără o cerere TGT legitimă corelată. Indică o posibilă utilizare a unui bilet Kerberos falsificat (Golden Ticket).",
                    TargetAccount = "SYSTEM / Delegated Admin",
                    ClientIp = "Localhost",
                    MitreTechniqueId = "T1558.001",
                    ContainmentActionRo = "1. Rotiți imediat cheile contului KRBTGT.\n2. Auditați lista de tichete Kerberos active pe Domain Controller folosind 'klist'.",
                    DetectedAt = specialPrivLogons.Max(r => r.TimeCreated)
                });
            }

            // 6. ADAUDIT: Modificare Grupuri Privilegiate (EID 4728 / 4732 / 4756 - Domain Admins, Enterprise Admins)
            var groupEvents = eventList.Where(e => e.EventId == 4728 || e.EventId == 4732 || e.EventId == 4756).ToList();
            if (groupEvents.Count > 0)
            {
                findings.Add(new KerberosAdFinding
                {
                    AttackType = "ADAudit: Adăugare Membru în Grup Privilegiat (Domain / Enterprise Admins)",
                    Category = "Privilege Escalation",
                    Severity = "Critical",
                    Description = $"Detectată adăugarea de membri în grupuri de securitate privilegiate (EID {string.Join(", ", groupEvents.Select(g => g.EventId).Distinct())}). Necesită audit imediat pentru prevenirea persistenței atacatorului cu drepturi administrative depline.",
                    TargetAccount = "Privileged Security Group",
                    ClientIp = "Domain Controller",
                    MitreTechniqueId = "T1098",
                    ContainmentActionRo = "1. Verificați dacă modificarea a fost autorizată prin Change Management.\n2. Eliminați contul adăugat dacă nu există tichet aprobat.\n3. Auditați contul de administrator care a efectuat modificarea.",
                    DetectedAt = groupEvents.Max(g => g.TimeCreated)
                });
            }

            // 7. ADAUDIT: Blocare Conturi în Masă / Password Spraying (EID 4740)
            var lockoutEvents = eventList.Where(e => e.EventId == 4740).ToList();
            if (lockoutEvents.Count >= 3)
            {
                findings.Add(new KerberosAdFinding
                {
                    AttackType = "ADAudit: Blocare Conturi în Masă (Account Lockout / Password Spraying)",
                    Category = "Credential Access",
                    Severity = "High",
                    Description = $"Detectat un număr de {lockoutEvents.Count} conturi blocate prin depășirea numărului maxim de parole incorecte. Indică un posibil atac de tip Password Spraying sau Brute Force distribuit.",
                    TargetAccount = "Multiple User Accounts",
                    ClientIp = "Rețea Internă / Edge",
                    MitreTechniqueId = "T1110.003",
                    ContainmentActionRo = "1. Identificați stația sau adresa IP sursă a încercărilor de autentificare (Event ID 4776 / 4625).\n2. Deblocați conturile legitime după resetarea parolei.\n3. Blocați adresa IP sursă la nivel de rețea.",
                    DetectedAt = lockoutEvents.Max(l => l.TimeCreated)
                });
            }

            // 8. ADAUDIT: Modificare Politici de Securitate GPO (EID 4739 / 5136)
            var gpoEvents = eventList.Where(e => e.EventId == 4739 || e.EventId == 5136).ToList();
            if (gpoEvents.Count > 0)
            {
                findings.Add(new KerberosAdFinding
                {
                    AttackType = "ADAudit: Modificare Politică Domeniu GPO (Password Policy / Lockout Policy)",
                    Category = "Defense Evasion / Policy Tampering",
                    Severity = "High",
                    Description = $"Detectată modificarea politicilor globale de securitate ale domeniului Active Directory (EID 4739 / 5136). Modificările pot include slăbirea complexității parolelor, eliminarea pragului de lockout sau permiterea NTLMv1.",
                    TargetAccount = "Default Domain Policy / GPO",
                    ClientIp = "Domain Controller",
                    MitreTechniqueId = "T1484.001",
                    ContainmentActionRo = "1. Examinați istoricul versiunilor GPO pentru a identifica modificările exacte.\n2. Reinițializați GPO din backup-ul securizat aprobat.\n3. Auditați permisiunile de editare GPO (Delegation permissions).",
                    DetectedAt = gpoEvents.Max(g => g.TimeCreated)
                });
            }

            // 9. ADAUDIT: Creare Cont Utilizator în Afara Programului / Neautorizat (EID 4720)
            var userCreatedEvents = eventList.Where(e => e.EventId == 4720).ToList();
            if (userCreatedEvents.Count > 0)
            {
                findings.Add(new KerberosAdFinding
                {
                    AttackType = "ADAudit: Creare Cont Nou Utilizator în Active Directory (EID 4720)",
                    Category = "Account Provisioning",
                    Severity = "Medium",
                    Description = $"Înregistrate {userCreatedEvents.Count} conturi noi de utilizator create în Active Directory. Necesită corelare cu aprobările de HR/IT Service Desk pentru a elimina conturile 'rogue' de persistență.",
                    TargetAccount = "New AD User Account",
                    ClientIp = "Domain Controller",
                    MitreTechniqueId = "T1136.001",
                    ContainmentActionRo = "1. Verificați validitatea cererii de creare cont în sistemul de ticketing.\n2. Dacă este neautorizat, dezactivați imediat contul (Disable Account).\n3. Investigați contul creator.",
                    DetectedAt = userCreatedEvents.Max(u => u.TimeCreated)
                });
            }

            return findings;
        }
    }
}
