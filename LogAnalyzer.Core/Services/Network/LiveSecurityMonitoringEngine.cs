using System;
using System.Collections.Generic;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services.Network
{
    public class LiveSecurityMonitoringEngine
    {
        private readonly List<string> _failedLogonHistory = new();
        private DateTime _lastCleanupUtc = DateTime.UtcNow;

        /// <summary>
        /// Evaluează în memorie un eveniment nou sosit în timp real și returnează o alertă dacă se detectează un atac sau anomalie.
        /// </summary>
        public DetectedIssue? EvaluateLiveEvent(ParsedEvent ev)
        {
            if (ev == null) return null;

            string msg = (ev.Message ?? string.Empty).ToLowerInvariant();
            string provider = (ev.ProviderName ?? string.Empty).ToLowerInvariant();

            // 1. Phishing & Malicious Payload Staging (T1566 / T1204 / T1105)
            if (msg.Contains("certutil") && (msg.Contains("urlcache") || msg.Contains("-f http")) ||
                msg.Contains("mshta") && (msg.Contains("http://") || msg.Contains("https://")) ||
                msg.Contains("curl") && (msg.Contains("http://") || msg.Contains("https://")) && (msg.Contains("-o") || msg.Contains(">")) ||
                (msg.Contains("downloads") || msg.Contains("appdata\\local\\temp")) && (msg.Contains(".iso") || msg.Contains(".hta") || msg.Contains(".vbs") || msg.Contains(".lnk") || msg.Contains(".js")) && (msg.Contains("wscript") || msg.Contains("cscript")) ||
                msg.Contains("tentativa phishing") || msg.Contains("phishing") || msg.Contains("simulare phishing"))
            {
                return new DetectedIssue
                {
                    Title = "🎣 ALERTĂ CRITICĂ: Tentativă de Phishing / Descărcare Payload Malițios",
                    Severity = "Critical",
                    MitreTechniqueId = "T1566.001",
                    MitreTacticName = "Initial Access",
                    Explanation = $"A fost interceptată o tentativă de phishing / inginerie socială sau descărcare de payload din sursă externă pe [{ev.MachineName}]. Se recomandă izolarea imediată și blocarea conexiunilor C2.",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 2. Ransomware & Shadow Copy Deletion (EID 4688 / Sysmon 1 / PowerShell 4104)
            if (msg.Contains("vssadmin") && (msg.Contains("delete") || msg.Contains("shadows")) ||
                msg.Contains("bcdedit") && msg.Contains("recoveryenabled") ||
                msg.Contains("wbadmin") && msg.Contains("delete") && msg.Contains("catalog"))
            {
                return new DetectedIssue
                {
                    Title = "🚨 ALERTĂ CRITICĂ: Tentativă Distrugere Shadow Copies (Ransomware)",
                    Severity = "Critical",
                    MitreTechniqueId = "T1490",
                    MitreTacticName = "Impact",
                    Explanation = $"Detectată execuția comenzii de distrugere a copiilor de rezervă pe hostul [{ev.MachineName}]. Tehnica este caracteristică etapelor premergătoare criptării de către grupările de Ransomware (LockBit, BlackCat, Akira).",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 2. PowerShell Codificat / Obfuscat / Download Cradle / Bypass (EID 4104 / EID 4688 / Sysmon 1 / Engine 400)
            if (msg.Contains("-enc") || msg.Contains("-encodedcommand") || msg.Contains("downloadstring") || 
                msg.Contains("iex(") || msg.Contains("bypass") || msg.Contains("downloadfile") ||
                msg.Contains("invoke-webrequest") || msg.Contains("invoke-expression") || msg.Contains("w hidden") ||
                (provider.Contains("powershell") && (msg.Contains("scriptblock") && msg.Contains("-enc"))))
            {
                return new DetectedIssue
                {
                    Title = "🚨 ALERTĂ MARE: Execuție PowerShell Codificat / Download Cradle",
                    Severity = "High",
                    MitreTechniqueId = "T1059.001",
                    MitreTacticName = "Execution",
                    Explanation = $"A fost interceptată o execuție suspectă de script PowerShell ascuns/obfuscat pe [{ev.MachineName}]. Comanda încearcă descărcarea de payload direct în memorie sau eludarea politicilor de execuție.",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 3. Acces Memorie LSASS / Mimikatz / Procdump
            if (msg.Contains("lsass.exe") && (msg.Contains("0x1010") || msg.Contains("0x1fffff") || msg.Contains("mimikatz") || msg.Contains("sekurlsa") || msg.Contains("logonpasswords")))
            {
                return new DetectedIssue
                {
                    Title = "🚨 ALERTĂ CRITICĂ: Tentativă Extragere Credențiale LSASS (Mimikatz / Dump)",
                    Severity = "Critical",
                    MitreTechniqueId = "T1003.001",
                    MitreTacticName = "Credential Access",
                    Explanation = $"Un proces a solicitat drepturi de acces la memoria procesului de autentificare LSASS pe [{ev.MachineName}]. Indicator puternic de atac cu unelte de tip Mimikatz sau Procdump.",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 4. Recunoaștere Privilegii / Utilizatori (whoami /priv, net user, net localgroup administrators)
            if (msg.Contains("whoami") && (msg.Contains("/priv") || msg.Contains("/all") || msg.Contains("/groups")) ||
                msg.Contains("net localgroup") && msg.Contains("administrators") ||
                msg.Contains("net group \"domain admins\""))
            {
                return new DetectedIssue
                {
                    Title = "⚠️ ALERTĂ MEDIE: Activitate de Recunoaștere & Enumerare Privilegii (Discovery)",
                    Severity = "Medium",
                    MitreTechniqueId = "T1033",
                    MitreTacticName = "Discovery",
                    Explanation = $"Comandă de enumerare a privilegiilor utilizatorului sau a membrilor grupurilor de administratori executată pe [{ev.MachineName}].",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 5. Creare Cont Administrator Nou (EID 4720 + EID 4732)
            if (ev.EventId == 4720 || ev.EventId == 4732 || (msg.Contains("net user") && msg.Contains("/add")))
            {
                return new DetectedIssue
                {
                    Title = "⚠️ ALERTĂ MEDIE: Creare / Modificare Cont Utilizator sau Grup Privilegiat",
                    Severity = "Medium",
                    MitreTechniqueId = "T1136.001",
                    MitreTacticName = "Persistence",
                    Explanation = $"A fost creat un cont local nou sau a fost adăugat un membru într-un grup administrativ pe [{ev.MachineName}].",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 6. Curățare Jurnal de Securitate (Anti-Forensics EID 1102 / 104)
            if (ev.EventId == 1102 || ev.EventId == 104 || (msg.Contains("wevtutil") && (msg.Contains("cl") || msg.Contains("clear-log"))))
            {
                return new DetectedIssue
                {
                    Title = "🚨 ALERTĂ CRITICĂ: Jurnal de Securitate Șters Intenționat (Anti-Forensics)",
                    Severity = "Critical",
                    MitreTechniqueId = "T1070.001",
                    MitreTacticName = "Defense Evasion",
                    Explanation = $"Jurnalul Security a fost curățat intenționat (wevtutil cl / Event Log Cleared) pe [{ev.MachineName}]. Tehnică standard de acoperire a urmelor după compromitere.",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 7. Instalare Serviciu Nou / Lateral Movement (EID 7045)
            if (ev.EventId == 7045 || msg.Contains("psexec") || msg.Contains("psexesvc"))
            {
                bool isPsExec = msg.Contains("psexec") || msg.Contains("psexesvc");
                return new DetectedIssue
                {
                    Title = isPsExec ? "🚨 ALERTĂ MARE: Serviciu de Execuție la Distanță (PsExec / Lateral Movement)" : "⚠️ NOTIFICARE: Serviciu Nou Instalat în Sistem",
                    Severity = isPsExec ? "High" : "Low",
                    MitreTechniqueId = "T1543.003",
                    MitreTacticName = "Persistence",
                    Explanation = $"A fost înregistrat un nou serviciu de sistem pe [{ev.MachineName}]. {ev.Message}",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 8. Eșecuri Repetate de Autentificare / Brute Force (EID 4625)
            if (ev.EventId == 4625)
            {
                TrackFailedLogon(ev.MachineName ?? "Unknown");
                if (_failedLogonHistory.Count >= 5)
                {
                    return new DetectedIssue
                    {
                        Title = "🚨 ALERTĂ MARE: Atac de Tip Brute Force / Password Spraying Detectat",
                        Severity = "High",
                        MitreTechniqueId = "T1110.001",
                        MitreTacticName = "Credential Access",
                        Explanation = $"Au fost interceptate {_failedLogonHistory.Count} autentificări eșuate consecutive într-un interval scurt pe [{ev.MachineName}].",
                        CreatedAt = DateTime.UtcNow,
                        RelatedEvents = new List<ParsedEvent> { ev }
                    };
                }
            }

            // 9. Exploits Kernel Ring 0 / BYOVD - Bring Your Own Vulnerable Driver (T1068 / T1543.003)
            if (msg.Contains("gdrv.sys") || msg.Contains("mhyprot2.sys") || msg.Contains("procexp152.sys") || 
                msg.Contains("dbutil") || msg.Contains("rtcore64.sys") || msg.Contains("kprocesshacker") ||
                msg.Contains("byovd") || msg.Contains("loldrivers") || 
                (msg.Contains("kernel driver") && (msg.Contains("installed") || msg.Contains("service installed") || msg.Contains("vulnerable driver"))))
            {
                return new DetectedIssue
                {
                    Title = "☣️ ALERTĂ CRITICĂ: Tentativă Încărcare Driver Kernel Vulnerabil (BYOVD / Ring 0)",
                    Severity = "Critical",
                    MitreTechniqueId = "T1068 / T1543.003",
                    MitreTacticName = "Privilege Escalation",
                    Explanation = $"A fost detectată tentativa de încărcare a unui driver de sistem vulnerabil cunoscut (BYOVD - Bring Your Own Vulnerable Driver) pe [{ev.MachineName}]. Atacatorii folosesc această tehnică pentru a eluda EDR-ul și a obține execuție de cod la nivel de Kernel Ring 0.",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 10. Injecții Exclusiv în Memorie / Process Hollowing (T1055 / T1055.012)
            if (msg.Contains("process hollowing") || msg.Contains("reflective dll") || msg.Contains("process injection") ||
                msg.Contains("virtualalloc") && (msg.Contains("page_execute_readwrite") || msg.Contains("0x40") || msg.Contains("writeprocessmemory")) ||
                msg.Contains("injected") && (msg.Contains("notepad") || msg.Contains("calc") || msg.Contains("svchost") || msg.Contains("spoolsv") || msg.Contains("werfault")))
            {
                return new DetectedIssue
                {
                    Title = "💉 ALERTĂ CRITICĂ: Injecție Exclusivă în Memorie & Process Hollowing",
                    Severity = "Critical",
                    MitreTechniqueId = "T1055.012",
                    MitreTacticName = "Defense Evasion",
                    Explanation = $"A fost detectată o anomalie gravă de memorie RAM pe [{ev.MachineName}]: un proces legitim de sistem a fost golit și injectat cu cod malițios direct în memorie fără scriere de fișiere pe disc (Process Hollowing).",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 11. Atac Fizic / Hardware (BadUSB / Rubber Ducky HID Injection T1052)
            if (msg.Contains("rubber ducky") || msg.Contains("badusb") || msg.Contains("hid keyboard") || 
                (msg.Contains("usb") && (msg.Contains("keystroke") || msg.Contains("payload injection"))))
            {
                return new DetectedIssue
                {
                    Title = "🔌 ALERTĂ CRITICĂ: Atac Fizic BadUSB / Rubber Ducky (HID Keystroke Injection)",
                    Severity = "Critical",
                    MitreTechniqueId = "T1052.001",
                    MitreTacticName = "Initial Access",
                    Explanation = $"A fost detectat un dispozitiv hardware neautorizat care simulează tastarea umană la viteză mare (BadUSB/Rubber Ducky) încercând injectarea de comenzi pe [{ev.MachineName}].",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 12. Furt Sesiuni, Infostealere & Bypass MFA (AiTM / Evilginx / Token Theft T1556 / T1539)
            if (msg.Contains("evilginx") || msg.Contains("evilproxy") || msg.Contains("lumma") || msg.Contains("redline") || 
                msg.Contains("stealc") || (msg.Contains("cookie") && (msg.Contains("theft") || msg.Contains("exfiltrat"))) ||
                (msg.Contains("appdata") && (msg.Contains("login data") || msg.Contains("web data")) && msg.Contains("sqlite")))
            {
                return new DetectedIssue
                {
                    Title = "🍪 ALERTĂ CRITICĂ: Furt Token-uri Sesiune & Bypass MFA (Infostealer / AiTM)",
                    Severity = "Critical",
                    MitreTechniqueId = "T1539 / T1556",
                    MitreTacticName = "Credential Access",
                    Explanation = $"Tentativă de extragere a bazelor de date cu credențiale și cookie-uri de sesiune OAuth/MFA din browser pe [{ev.MachineName}].",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 13. Otrăvire Rețea Locală & Captură NTLM (LLMNR / NBT-NS Poisoning - Responder T1557.001)
            if (msg.Contains("responder") || msg.Contains("llmnr") || msg.Contains("nbt-ns") || msg.Contains("inveigh") || msg.Contains("ntlm relay"))
            {
                return new DetectedIssue
                {
                    Title = "📡 ALERTĂ MARE: Otrăvire Rețea Locală & Captură NTLM (Responder / LLMNR Poisoning)",
                    Severity = "High",
                    MitreTechniqueId = "T1557.001",
                    MitreTacticName = "Credential Access",
                    Explanation = $"Activitate malițioasă de broadcast/spoofing LLMNR/NBT-NS detectată în subrețea pe [{ev.MachineName}]. Un atacator interceptează hash-urile de autentificare NTLMv2.",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 14. Abuz de Token-uri & Escaladare Privilegii (PrintSpoofer / Potato Exploits T1134)
            if (msg.Contains("printspoofer") || msg.Contains("juicypotato") || msg.Contains("godpotato") || 
                (msg.Contains("seimpersonateprivilege") && (msg.Contains("escalat") || msg.Contains("system"))))
            {
                return new DetectedIssue
                {
                    Title = "🥔 ALERTĂ CRITICĂ: Escaladare Privilegii prin Abuz Token-uri (Potato / SeImpersonate)",
                    Severity = "Critical",
                    MitreTechniqueId = "T1134.001",
                    MitreTacticName = "Privilege Escalation",
                    Explanation = $"Tentativă de escaladare la NT AUTHORITY\\SYSTEM prin exploatarea dreptului SeImpersonatePrivilege pe [{ev.MachineName}].",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 15. Reguli Ascunse Cloud & Exfiltrare Email (M365 Forwarding Rules T1114.003)
            if (msg.Contains("inboxrule") || msg.Contains("forwardingrule") || (msg.Contains("oauth") && msg.Contains("mail.readwrite")))
            {
                return new DetectedIssue
                {
                    Title = "☁️ ALERTĂ MARE: Reguli Ascunse de Redirecționare Email & Exfiltrare Cloud",
                    Severity = "High",
                    MitreTechniqueId = "T1114.003",
                    MitreTacticName = "Collection",
                    Explanation = $"Regulă automată suspectă de copiere/redirecționare a mesajelor de email către o destinație externă neautorizată pe [{ev.MachineName}].",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 16. Hardware Side-Channel & Anomalie Fizică (Rowhammer / Speculative Execution T1499)
            if (msg.Contains("rowhammer") || msg.Contains("spectre") || msg.Contains("meltdown") || msg.Contains("zenbleed") || msg.Contains("downfall") || msg.Contains("cpu silicon"))
            {
                return new DetectedIssue
                {
                    Title = "🔬 ALERTĂ CRITICĂ: Atac pe Siliciu CPU & Memorie Fizică (Rowhammer / Spectre)",
                    Severity = "Critical",
                    MitreTechniqueId = "T1499 / CPU Silicon",
                    MitreTacticName = "Defense Evasion",
                    Explanation = $"Anomalie critică de microarhitectură pe siliciu detectată (Rowhammer DRAM bit-flip sau Speculative Execution Cache Leak) pe [{ev.MachineName}].",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 17. Air-Gap Săritură & Exfiltrare Acustică / Ventilatoare (Fansmitter / Covert Channel T1048)
            if (msg.Contains("fansmitter") || msg.Contains("acoustic") || msg.Contains("ventilatoare") || 
                msg.Contains("pwm fan") || msg.Contains("air-gap covert channel") || msg.Contains("tempest"))
            {
                return new DetectedIssue
                {
                    Title = "🔊 ALERTĂ CRITICĂ: Exfiltrare Acustică prin Modulație Ventilatoare (Air-Gap Jumping / Fansmitter)",
                    Severity = "Critical",
                    MitreTechniqueId = "T1048 / T1052 (Air-Gap)",
                    MitreTacticName = "Exfiltration",
                    Explanation = $"Tentativă de transmitere de date confidențiale din sistem izolat prin vibrații acustice generate de modulația PWM a ventilatoarelor pe [{ev.MachineName}]. Conform normelor HG 585 / NATO TEMPEST.",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            // 18. Comenzi de Test / Simulare
            if (msg.Contains("simulare dfir") || msg.Contains("test alert"))
            {
                return new DetectedIssue
                {
                    Title = "🚨 ALERTĂ LIVE (TEST SIMULAT): Detecție Semnătură Activă",
                    Severity = "High",
                    MitreTechniqueId = "T1059.001",
                    MitreTacticName = "Execution",
                    Explanation = $"A fost interceptată o simulare de alertă de securitate live pe [{ev.MachineName}]. Pipeline-ul de detecție și toast pop-up funcționează perfect.",
                    CreatedAt = DateTime.UtcNow,
                    RelatedEvents = new List<ParsedEvent> { ev }
                };
            }

            return null;
        }

        private void TrackFailedLogon(string machineName)
        {
            if ((DateTime.UtcNow - _lastCleanupUtc).TotalMinutes > 2)
            {
                _failedLogonHistory.Clear();
                _lastCleanupUtc = DateTime.UtcNow;
            }
            _failedLogonHistory.Add(machineName);
        }
    }
}
