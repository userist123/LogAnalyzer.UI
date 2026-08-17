using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class ForensicEventAssessment
    {
        public string TitleRo { get; set; } = string.Empty;
        public string ThreatScenarioRo { get; set; } = string.Empty;
        public string MitreTtpRo { get; set; } = string.Empty;
        public string ForensicDetailsRo { get; set; } = string.Empty;
        public string ContainmentPlaybookRo { get; set; } = string.Empty;
        public string SeverityRo { get; set; } = "Informativ";
        public string RiskColor { get; set; } = "#38bdf8";
    }

    public static class ForensicEventKnowledgeService
    {
        public static ForensicEventAssessment GetAssessment(ParsedEvent ev)
        {
            var assessment = new ForensicEventAssessment();
            if (ev == null) return assessment;

            int eid = ev.EventId;
            string msg = ev.Message ?? string.Empty;
            string msgLower = msg.ToLowerInvariant();
            string xml = ev.XmlData ?? string.Empty;

            // Extragem proprietăți cheie din XML sau Message
            string logonType = ExtractXmlField(xml, "LogonType");
            string targetUser = ExtractXmlField(xml, "TargetUserName");
            if (string.IsNullOrEmpty(targetUser)) targetUser = ExtractXmlField(xml, "SubjectUserName");
            string processName = ExtractXmlField(xml, "NewProcessName");
            if (string.IsNullOrEmpty(processName)) processName = ExtractXmlField(xml, "ProcessName");
            string commandLine = ExtractXmlField(xml, "CommandLine");
            string ipAddress = ExtractXmlField(xml, "IpAddress");

            switch (eid)
            {
                // ==================== AUTENTIFICARE ȘI ACCES ====================
                case 4624:
                    string logonDesc = logonType switch
                    {
                        "2" => "Tip 2 (Interactiv Local - utilizatorul s-a logat fizic de la tastatură)",
                        "3" => "Tip 3 (Rețea - acces prin SMB/Share sau autentificare NTLM/Kerberos)",
                        "4" => "Tip 4 (Batch - sarcină programată sau script de fundal)",
                        "5" => "Tip 5 (Serviciu - proces de sistem care rulează ca serviciu)",
                        "7" => "Tip 7 (Deblocare Ecran - stația a fost deblocată)",
                        "8" => "Tip 8 (NetworkCleartext - parolă trimisă în clar prin rețea)",
                        "9" => "Tip 9 (NewCredentials - utilizare 'runas /netonly' sau Mimikatz PTH)",
                        "10" => "Tip 10 (RemoteInteractive - sesiune RDP conectată de la distanță)",
                        "11" => "Tip 11 (CachedInteractive - logare cu credențiale salvate în cache)",
                        _ => $"Tip {logonType} (Autentificare standard de sistem)"
                    };
                    assessment.TitleRo = "Autentificare Reușită în Sistem (Logon)";
                    assessment.ThreatScenarioRo = $"Sesiune nouă deschisă pentru utilizatorul [{targetUser}] pe mașina [{ev.MachineName}]. {logonDesc}. În cazul în care sesiunea provine de la un IP extern ({ipAddress}) sau de Tip 10 (RDP) în afara orelor de lucru, poate indica acces neautorizat sau mișcare laterală.";
                    assessment.MitreTtpRo = "Initial Access / Lateral Movement - Valid Accounts (T1078)";
                    assessment.ForensicDetailsRo = $"Utilizator: {targetUser} | Tip Logon: {logonType} | IP Sursă: {ipAddress} | Dispozitiv: {ev.MachineName}";
                    assessment.ContainmentPlaybookRo = "1. Verificați dacă utilizatorul a inițiat legitim sesiunea.\n2. Dacă IP-ul sursă este extern sau necunoscut, deconectați sesiunea și forțați resetarea parolei.\n3. Auditați evenimentele 4688 (procese create) din intervalul imediat următor logării.";
                    assessment.SeverityRo = logonType == "10" || logonType == "9" ? "Atenție" : "Informativ";
                    assessment.RiskColor = logonType == "10" ? "#f59e0b" : "#22c55e";
                    break;

                case 4625:
                    assessment.TitleRo = "Tentativă Eșuată de Autentificare (Logon Failure)";
                    assessment.ThreatScenarioRo = $"Autentificare respinsă pentru contul [{targetUser}] de la IP-ul [{ipAddress}]. Apariția frecventă a acestui eveniment semnalează atacuri automate de tip Brute Force, Password Spraying sau utilizarea de credențiale compromise.";
                    assessment.MitreTtpRo = "Credential Access - Password Guessing / Spraying (T1110.001 / T1110.003)";
                    assessment.ForensicDetailsRo = $"Cont Țintă: {targetUser} | IP Atacator: {ipAddress} | Motiv Eșec: Cod status de autentificare invalid.";
                    assessment.ContainmentPlaybookRo = "1. Blocați imediat IP-ul sursă în Firewall-ul perimetral.\n2. Verificați dacă contul vizat a fost blocat automat prin politica de lockout.\n3. Notificați posesorul contului și auditați jurnalele VPN/RDP.";
                    assessment.SeverityRo = "Ridicată";
                    assessment.RiskColor = "#ef4444";
                    break;

                case 4648:
                    assessment.TitleRo = "Autentificare Explicită cu Credențiale Alternative (RunAs / PTH)";
                    assessment.ThreatScenarioRo = $"Un proces a încercat să se autentifice specificând explicit credențialele contului [{targetUser}]. Comportament frecvent utilizat în atacurile de tip Pass-the-Hash, comenzile 'runas' sau instrumentele de hacking (Cobalt Strike, CrackMapExec).";
                    assessment.MitreTtpRo = "Privilege Escalation / Lateral Movement - Alternate Authentication Credentials (T1550)";
                    assessment.ForensicDetailsRo = $"Cont Sursă: {ExtractXmlField(xml, "SubjectUserName")} | Cont Țintă Utilizat: {targetUser} | Proces Apelant: {processName}";
                    assessment.ContainmentPlaybookRo = "1. Identificați procesul care a furnizat credențialele.\n2. Verificați dacă acțiunea a fost executată de un administrator IT legitim.\n3. În caz de dubiu, izolați stația și terminați procesul suspect.";
                    assessment.SeverityRo = "Ridicată";
                    assessment.RiskColor = "#f97316";
                    break;

                case 4672:
                    assessment.TitleRo = "Privilegii Speciale / Administrative Atribuite la Logon";
                    assessment.ThreatScenarioRo = $"Contului [{targetUser}] i-au fost atribuite drepturi depline de administrator (ex: SeDebugPrivilege, SeTcbPrivilege, SeSecurityPrivilege). Aceste drepturi permit accesul la memoria tuturor proceselor (inclusiv LSASS) și modificarea nucleului sistemului.";
                    assessment.MitreTtpRo = "Privilege Escalation - Superuser Privileges (T1078.003)";
                    assessment.ForensicDetailsRo = $"Utilizator: {targetUser} | Drepturi acordate: Drepturi complete de Debug / Admin pe {ev.MachineName}.";
                    assessment.ContainmentPlaybookRo = "1. Asigurați-vă că utilizatorul face parte legitim din grupul 'Domain Admins' sau 'Administrators'.\n2. Urmăriți dacă utilizatorul a deschis un utilitar de dumping memorie.";
                    assessment.SeverityRo = "Medie";
                    assessment.RiskColor = "#f59e0b";
                    break;

                // ==================== CREARE ȘI EXECUȚIE PROCESE ====================
                case 4688:
                    bool isSuspiciousCmd = msgLower.Contains("-enc") || msgLower.Contains("bypass") || msgLower.Contains("downloadstring") || msgLower.Contains("vssadmin") || msgLower.Contains("mimikatz") || msgLower.Contains("whoami") || msgLower.Contains("net user");
                    assessment.TitleRo = isSuspiciousCmd ? "Execuție Proces cu Argumente Suspecte (Threat Activity)" : "Proces Nou Inițiat în Sistem";
                    assessment.ThreatScenarioRo = isSuspiciousCmd 
                        ? $"A fost lansat un proces cu o linie de comandă suspectă pe [{ev.MachineName}]: {commandLine}. Acest tipar este specific atacatorilor care încearcă recunoașterea rețelei, descărcarea de payload-uri sau bypass-ul securității."
                        : $"Procesul [{processName}] a fost creat de către procesul părinte [{ExtractXmlField(xml, "ParentProcessName")}].";
                    assessment.MitreTtpRo = isSuspiciousCmd ? "Execution - Command and Scripting Interpreter (T1059.001)" : "Execution - Process Creation (T1204)";
                    assessment.ForensicDetailsRo = $"Executabil: {processName} | Linie Comandă: {commandLine} | Utilizator: {targetUser}";
                    assessment.ContainmentPlaybookRo = isSuspiciousCmd
                        ? "1. Generați scriptul 'Kill-ProcessTree.ps1' pentru a termina procesul și copiii acestuia.\n2. Salvați un dump de memorie RAM pentru analiză statică și dinamică.\n3. Blocați hash-ul executabilului în EDR/AppLocker."
                        : "1. Monitorizați conexiunile de rețea deschise de proces.\n2. Verificați semnătura digitală a fișierului executabil.";
                    assessment.SeverityRo = isSuspiciousCmd ? "Critică" : "Informativ";
                    assessment.RiskColor = isSuspiciousCmd ? "#ef4444" : "#22c55e";
                    break;

                case 4104:
                case 4103:
                    assessment.TitleRo = "Execuție Bloc Script PowerShell (Script Block Logging)";
                    assessment.ThreatScenarioRo = $"PowerShell a executat un bloc de cod în memorie pe [{ev.MachineName}]. Dacă scriptul conține tehnici de descărcare (`DownloadString`, `IEX`), injectare memorie sau dezactivare Defender, reprezintă o amenințare critică activă.";
                    assessment.MitreTtpRo = "Execution - PowerShell Scripting (T1059.001)";
                    assessment.ForensicDetailsRo = $"Conținut Cod Script: {ev.Message}";
                    assessment.ContainmentPlaybookRo = "1. Analizați codul scriptului pentru extragerea URL-urilor C2 sau payload-urilor Base64.\n2. Rulați un scan cu YARA Engine pe memorie.\n3. Dezactivați accesul la PowerShell pentru utilizatorii non-administratori.";
                    assessment.SeverityRo = msgLower.Contains("bypass") || msgLower.Contains("download") ? "Critică" : "Medie";
                    assessment.RiskColor = "#ef4444";
                    break;

                // ==================== PERSISTENȚĂ ȘI SERVICII ====================
                case 7045:
                case 4697:
                    assessment.TitleRo = "Serviciu de Sistem Nou Instalat (Persistence / PrivEsc)";
                    assessment.ThreatScenarioRo = $"Un serviciu Windows nou a fost configurat pe [{ev.MachineName}]. Atacatorii instalează servicii malițioase pentru a obține persistență garantată la repornirea sistemului și pentru a rula cod cu privilegii de 'NT AUTHORITY\\SYSTEM'.";
                    assessment.MitreTtpRo = "Persistence / Privilege Escalation - Windows Service (T1543.003)";
                    assessment.ForensicDetailsRo = $"Nume Serviciu: {ExtractXmlField(xml, "ServiceName")} | Cale Binar (ImagePath): {ExtractXmlField(xml, "ImagePath")} | Utilizator: {targetUser}";
                    assessment.ContainmentPlaybookRo = "1. Opriți imediat serviciul prin comanda: 'Stop-Service -Name [Nume] -Force'.\n2. Ștergeți serviciul: 'sc.exe delete [Nume]'.\n3. Trimiteți fișierul binar asociat la analiza antivirus/sandbox.";
                    assessment.SeverityRo = "Ridicată";
                    assessment.RiskColor = "#f97316";
                    break;

                case 4720:
                    assessment.TitleRo = "Cont Nou de Utilizator Creat (Account Creation)";
                    assessment.ThreatScenarioRo = $"Un cont de utilizator nou [{targetUser}] a fost creat pe [{ev.MachineName}] de către [{ExtractXmlField(xml, "SubjectUserName")}]. Crearea neprogramată de conturi este o metodă clasică de backdoor utilizată de atacatori după compromiterea inițială.";
                    assessment.MitreTtpRo = "Persistence - Local Account Creation (T1136.001)";
                    assessment.ForensicDetailsRo = $"Cont Creat: {targetUser} | Creat de: {ExtractXmlField(xml, "SubjectUserName")} | Stație: {ev.MachineName}";
                    assessment.ContainmentPlaybookRo = "1. Verificați cu echipa de Helpdesk dacă crearea contului a fost autorizată prin tichet oficial.\n2. Dacă este neautorizat, dezactivați contul imediat: 'Disable-LocalUser -Name [Cont]'.\n3. Auditați dacă contul a fost adăugat în grupuri de administratori.";
                    assessment.SeverityRo = "Ridicată";
                    assessment.RiskColor = "#ef4444";
                    break;

                case 4728:
                case 4732:
                    assessment.TitleRo = "Utilizator Adăugat în Grup Privilegiat (Privilege Escalation)";
                    assessment.ThreatScenarioRo = $"Contul [{ExtractXmlField(xml, "MemberName")}] a fost adăugat în grupul administrativ [{ExtractXmlField(xml, "TargetGroupName")}]. Permite utilizatorului să obțină control total asupra mașinii sau domeniului Active Directory.";
                    assessment.MitreTtpRo = "Privilege Escalation - Account Manipulation (T1098)";
                    assessment.ForensicDetailsRo = $"Membru Adăugat: {ExtractXmlField(xml, "MemberName")} | Grup Destinație: {ExtractXmlField(xml, "TargetGroupName")} | Executat de: {ExtractXmlField(xml, "SubjectUserName")}";
                    assessment.ContainmentPlaybookRo = "1. Eliminați imediat contul din grupul administrativ.\n2. Revocați sesiunile active și tichetele Kerberos ale contului.\n3. Investigați contul care a realizat modificarea pentru a vedea dacă a fost deturnat.";
                    assessment.SeverityRo = "Ridicată";
                    assessment.RiskColor = "#ef4444";
                    break;

                // ==================== ȘTERGERE URME ȘI DEFENSE EVASION ====================
                case 1102:
                case 104:
                    assessment.TitleRo = "Jurnal de Securitate Curățat Manual (Defense Evasion)";
                    assessment.ThreatScenarioRo = $"Jurnalul de evenimente de securitate a fost șters pe [{ev.MachineName}] de către utilizatorul [{ExtractXmlField(xml, "SubjectUserName")}]. Aceasta este o acțiune extrem de critică, utilizată aproape exclusiv de intruși pentru a elimina dovezile activității rău-intenționate.";
                    assessment.MitreTtpRo = "Defense Evasion - Clear Windows Event Logs (T1070.001)";
                    assessment.ForensicDetailsRo = $"Jurnal Șters: Security/System | Inițiator Acțiune: {ExtractXmlField(xml, "SubjectUserName")} | Echipament: {ev.MachineName}";
                    assessment.ContainmentPlaybookRo = "1. Tratați evenimentul ca pe un Incident de Securitate Confirmat de Severitate Maximă.\n2. Izolați imediat stația de la rețea pentru a preveni exfiltrarea.\n3. Recuperați logurile din backup sau din serverul centralizat SIEM/Syslog.";
                    assessment.SeverityRo = "Critică";
                    assessment.RiskColor = "#ef4444";
                    break;

                // ==================== ARTEFACTE DE TRIAGE FORENZIC ====================
                case 20101:
                    assessment.TitleRo = "Înregistrare Cache DNS (Triage Forenzic)";
                    assessment.ThreatScenarioRo = $"Rezoluție DNS identificată în cache-ul local al mașinii [{ev.MachineName}]. Domeniile cu nume aleatorii, Dynamic DNS sau TLD-uri suspecte (.xyz, .top, .ru) indică comunicație cu servere de Comandă și Control (C2).";
                    assessment.MitreTtpRo = "Command and Control - Application Layer Protocol: DNS (T1071.004)";
                    assessment.ForensicDetailsRo = $"Domeniu Interogat: {ev.Message}";
                    assessment.ContainmentPlaybookRo = "1. Blocați domeniul în serverele DNS interne (Sinkholing).\n2. Căutați adresa IP asociată în traficul de rețea (Firewall/Proxy).\n3. Verificați procesul care a generat interogarea DNS.";
                    assessment.SeverityRo = "Medie";
                    assessment.RiskColor = "#38bdf8";
                    break;

                case 20102:
                    assessment.TitleRo = "Driver de Kernel Identificat (BYOVD / Rootkit Audit)";
                    assessment.ThreatScenarioRo = $"Driver de nivel Ring 0 înregistrat în sistemul de operare pe [{ev.MachineName}]. Driverele nesemnate sau vulnerabile sunt exploatate de atacatori prin tehnici 'Bring Your Own Vulnerable Driver' (BYOVD) pentru a opri soluțiile EDR din nucleu.";
                    assessment.MitreTtpRo = "Defense Evasion / PrivEsc - Exploitation for Privilege Escalation (T1068)";
                    assessment.ForensicDetailsRo = $"Fișier Driver: {ev.Message}";
                    assessment.ContainmentPlaybookRo = "1. Verificați hash-ul SHA-256 al driverului pe baza de date loldrivers.io.\n2. Dacă este un driver vulnerabil cunoscut, dezactivați încărcarea acestuia.\n3. Activați funcționalitatea 'Driver Blocklist' în Windows Defender.";
                    assessment.SeverityRo = "Ridicată";
                    assessment.RiskColor = "#f97316";
                    break;

                case 20103:
                    assessment.TitleRo = "Sarcină Programată (Scheduled Task - Triage)";
                    assessment.ThreatScenarioRo = $"Sarcină programată identificată în Task Scheduler pe [{ev.MachineName}]. Sarcinile care apelează scripturi din directoare temporare (`%TEMP%`, `AppData`) sau utilizează LOLBins (`mshta.exe`, `powershell.exe`) indică persistență malware.";
                    assessment.MitreTtpRo = "Persistence / Execution - Scheduled Task (T1053.005)";
                    assessment.ForensicDetailsRo = $"Detalii Sarcină: {ev.Message}";
                    assessment.ContainmentPlaybookRo = "1. Ștergeți sarcina din Task Scheduler: 'Unregister-ScheduledTask -TaskName [Nume]'.\n2. Eliminați binarul sau scriptul apelat de pe disc.\n3. Verificați când a fost creată sarcina inițial.";
                    assessment.SeverityRo = "Medie";
                    assessment.RiskColor = "#f59e0b";
                    break;

                case 20105:
                    assessment.TitleRo = "Excludere Configurate în Antivirus Windows Defender";
                    assessment.ThreatScenarioRo = $"O cale de folder sau un proces a fost exclus de la scanarea automată a Windows Defender pe [{ev.MachineName}]. Atacatorii configurează excluderi pentru a rula malware fără a fi detectat.";
                    assessment.MitreTtpRo = "Defense Evasion - Impair Defenses: Disable or Modify Tools (T1562.001)";
                    assessment.ForensicDetailsRo = $"Excludere: {ev.Message}";
                    assessment.ContainmentPlaybookRo = "1. Eliminați imediat excluderea din setările Defender: 'Remove-MpPreference -ExclusionPath [Cale]'.\n2. Lansați o scanare completă: 'Start-MpScan -ScanType FullScan'.\n3. Identificați contul care a modificat politica Defender.";
                    assessment.SeverityRo = "Critică";
                    assessment.RiskColor = "#ef4444";
                    break;

                case 20109:
                    assessment.TitleRo = "Comandă extrasă din Istoricul PowerShell (ConsoleHost_history)";
                    assessment.ThreatScenarioRo = $"Comandă tastată manual sau rulată în consola utilizatorului pe [{ev.MachineName}]. Oferă vizibilitate directă asupra acțiunilor atacatorului sau ale operatorului uman în timpul intruziunii.";
                    assessment.MitreTtpRo = "Execution - Command and Scripting Interpreter (T1059.001)";
                    assessment.ForensicDetailsRo = $"Comandă Executată: {ev.Message}";
                    assessment.ContainmentPlaybookRo = "1. Evaluați comenzile consecutive rulate înainte și după acest eveniment.\n2. Identificați fișierele create sau descărcate prin comanda respectivă.\n3. Determinați dacă utilizatorul tastat a fost autorizat.";
                    assessment.SeverityRo = "Ridicată";
                    assessment.RiskColor = "#f97316";
                    break;

                case 20110:
                    assessment.TitleRo = "Dispozitiv USB Montat pe Sistem (USBSTOR Forensics)";
                    assessment.ThreatScenarioRo = $"Istoric al unui dispozitiv de stocare USB extern conectat pe [{ev.MachineName}]. Esențial pentru investigarea scurgerilor de date (Data Exfiltration) sau a infecțiilor introduse fizic prin stick-uri USB.";
                    assessment.MitreTtpRo = "Exfiltration / Initial Access - Replication Through Removable Media (T1091)";
                    assessment.ForensicDetailsRo = $"Dispozitiv USB: {ev.Message}";
                    assessment.ContainmentPlaybookRo = "1. Comparați numărul serial al stick-ului USB cu registrul de active al companiei.\n2. Auditați fișierele copiate pe dispozitiv în intervalul conectării.\n3. Aplicați politica GPO de restricționare a mediilor de stocare amovibile.";
                    assessment.SeverityRo = "Informativ";
                    assessment.RiskColor = "#38bdf8";
                    break;

                case 20111:
                    assessment.TitleRo = "Sesiune Activă RDP / Locală (qwinsta Triage)";
                    assessment.ThreatScenarioRo = $"Sesiune de lucru activă sau deconectată identificată pe mașina [{ev.MachineName}]. Permite identificarea utilizatorilor conectați concurent sau a sesiunilor RDP ascunse.";
                    assessment.MitreTtpRo = "Lateral Movement - Remote Desktop Protocol (T1021.001)";
                    assessment.ForensicDetailsRo = $"Sesiune: {ev.Message}";
                    assessment.ContainmentPlaybookRo = "1. Închideți sesiunile necunoscute sau inactive prin comanda 'logoff [ID]'.\n2. Limitați accesul RDP exclusiv prin conexiune VPN securizată cu MFA.";
                    assessment.SeverityRo = "Informativ";
                    assessment.RiskColor = "#38bdf8";
                    break;

                case 20112:
                    assessment.TitleRo = "Tabelă Rutare Rețea & Portproxy (Network Triage)";
                    assessment.ThreatScenarioRo = $"Regulă de rutare sau portproxy configurată pe [{ev.MachineName}]. Atacatorii configurează 'netsh interface portproxy' pentru a redirectiona traficul intern către mașini C2 din afara rețelei.";
                    assessment.MitreTtpRo = "Command and Control - Protocol Tunneling (T1572)";
                    assessment.ForensicDetailsRo = $"Configurație Rutare: {ev.Message}";
                    assessment.ContainmentPlaybookRo = "1. Ștergeți regulile de redirecționare neautorizate: 'netsh interface portproxy reset'.\n2. Auditați traficul direcționat pe portul țintă.";
                    assessment.SeverityRo = "Medie";
                    assessment.RiskColor = "#38bdf8";
                    break;

                // ==================== DEFAULT / FALLBACK INTELIGENT ====================
                default:
                    assessment.TitleRo = $"Eveniment de Sistem (EID {eid})";
                    assessment.ThreatScenarioRo = !string.IsNullOrWhiteSpace(ev.OfficialDescription) && ev.OfficialDescription.Length > 10
                        ? ev.OfficialDescription
                        : $"Activitate înregistrată de provider-ul [{ev.ProviderName}] pe mașina [{ev.MachineName}]. Evenimentul furnizează context operațional pentru reconstrucția liniei temporale forenzice.";
                    assessment.MitreTtpRo = !string.IsNullOrWhiteSpace(ev.PotentialCriticality) ? ev.PotentialCriticality : "Traseu de Audit Standard Windows";
                    assessment.ForensicDetailsRo = $"ID Eveniment: {eid} | Provider: {ev.ProviderName} | Nivel: {ev.Level} | Data: {ev.TimeCreated:yyyy-MM-dd HH:mm:ss}";
                    assessment.ContainmentPlaybookRo = "1. Examinați parametrii din tab-ul 'Proprietăți Parsate'.\n2. Comparați frecvența apariției cu starea normală a echipamentului.\n3. Corelați cu evenimentele adiacente din Cronologie.";
                    assessment.SeverityRo = ev.Level ?? "Informativ";
                    assessment.RiskColor = ev.Level?.Equals("Critical", StringComparison.OrdinalIgnoreCase) == true ? "#ef4444" :
                                          ev.Level?.Equals("High", StringComparison.OrdinalIgnoreCase) == true ? "#f97316" :
                                          ev.Level?.Equals("Warning", StringComparison.OrdinalIgnoreCase) == true ? "#f59e0b" : "#38bdf8";
                    break;
            }

            return assessment;
        }

        private static string ExtractXmlField(string xml, string fieldName)
        {
            if (string.IsNullOrWhiteSpace(xml)) return string.Empty;
            try
            {
                var match = Regex.Match(xml, $@"<Data Name=""{fieldName}"">([^<]*)</Data>", RegexOptions.IgnoreCase);
                if (match.Success) return match.Groups[1].Value;

                var elemMatch = Regex.Match(xml, $@"<{fieldName}>([^<]*)</{fieldName}>", RegexOptions.IgnoreCase);
                if (elemMatch.Success) return elemMatch.Groups[1].Value;
            }
            catch { }
            return string.Empty;
        }
    }
}
