using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services.Network
{
    public class CountermeasureAction
    {
        public string Title { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public string ActionType { get; set; } = string.Empty; // "Isolate", "KillProcess", "BlockIoC", "RevokeAuth"
        public string PowerShellSnippet { get; set; } = string.Empty;
        public bool IsRecommended { get; set; } = true;
    }

    public class AttackerIntelligenceDetails
    {
        public string SourceIpOrDomain { get; set; } = string.Empty;
        public string LikelyActorName { get; set; } = string.Empty;
        public string ActorCountryOrOrigin { get; set; } = string.Empty;
        public string Motivation { get; set; } = string.Empty;
        public string TargetUserOrAccount { get; set; } = string.Empty;
        public string AttackProcessPath { get; set; } = string.Empty;
        public string AttackHashSha256 { get; set; } = string.Empty;
        public string KnownToolsUsed { get; set; } = string.Empty;
        public string DefenseRecommendation { get; set; } = string.Empty;
    }

    public class CountermeasurePlaybook
    {
        public string AttackCategory { get; set; } = string.Empty;
        public string ThreatLevel { get; set; } = "Critical";
        public string ImmediateObjective { get; set; } = string.Empty;
        public AttackerIntelligenceDetails AttackerIntel { get; set; } = new();
        public List<CountermeasureAction> Actions { get; set; } = new();
        public string ForensicsGuidance { get; set; } = string.Empty;
    }

    public class CyberAttackCountermeasureEngine
    {
        /// <summary>
        /// Generează planul de combatere și acțiuni specifice pentru un atac detectat.
        /// </summary>
        public CountermeasurePlaybook GeneratePlaybook(DetectedIssue alert, string hostname = "localhost")
        {
            var playbook = new CountermeasurePlaybook
            {
                ThreatLevel = alert.Severity,
                AttackerIntel = ExtractDynamicAttackerIntel(alert, hostname)
            };

            string titleLower = (alert.Title ?? string.Empty).ToLowerInvariant();
            string tech = (alert.MitreTechniqueId ?? string.Empty).ToUpperInvariant();

            // 1. Phishing & Social Engineering (T1566 / T1059)
            if (titleLower.Contains("phishing") || tech.StartsWith("T1566") || titleLower.Contains("download cradle"))
            {
                playbook.AttackCategory = "🎣 Tentativă de Phishing & Descărcare Payload";
                playbook.ImmediateObjective = "Blocarea accesului la serverul atacatorului, oprirea descărcării de malware și prevenirea furtului de credențiale.";
                playbook.ForensicsGuidance = "Verificați folderul %TEMP% și Downloads pentru fișiere .LNK, .ISO, .VBS sau .HTA. Extrageți domeniul din comanda curl/powershell și adăugați-l pe lista neagră.";

                playbook.Actions.Add(new CountermeasureAction
                {
                    Title = "🚫 Blochează Conexiunile către Domeniul / IP-ul de Phishing",
                    Description = "Adaugă regulă de blocare pe Windows Firewall și rescrie DNS Hosts pentru a preveni contactarea serverului C2 de phishing.",
                    ActionType = "BlockIoC",
                    PowerShellSnippet = "New-NetFirewallRule -DisplayName 'DFIR_Block_Phishing_C2' -Direction Outbound -Action Block -RemoteAddress Any",
                    IsRecommended = true
                });

                playbook.Actions.Add(new CountermeasureAction
                {
                    Title = "🛑 Termină Procesul de Descărcare (PowerShell / mshta / curl)",
                    Description = "Oprește imediat procesul utilizat pentru descărcarea sau lansarea payload-ului de phishing.",
                    ActionType = "KillProcess",
                    PowerShellSnippet = "Get-Process -Name 'powershell','mshta','curl' -ErrorAction SilentlyContinue | Stop-Process -Force",
                    IsRecommended = true
                });

                playbook.Actions.Add(new CountermeasureAction
                {
                    Title = "🔑 Revocă Sesiunile & Forțează Resetarea Parolei",
                    Description = "În caz de inginerie socială sau phishing de credențiale, forțează resetarea parolei contului și invalidarea token-urilor de autentificare.",
                    ActionType = "RevokeAuth",
                    PowerShellSnippet = "Revoke-AzureADUserAllRefreshToken (sau net user [Utilizator] /logonpasswordchg:yes)",
                    IsRecommended = false
                });
            }
            // 2. Ransomware & Shadow Copy Deletion (T1490)
            else if (titleLower.Contains("ransomware") || tech == "T1490")
            {
                playbook.AttackCategory = "🚨 Atac de tip Ransomware (Criptare Date)";
                playbook.ImmediateObjective = "Izolarea instantanee a calculatorului din rețea pentru a opri propagarea laterală și protejarea share-urilor de rețea.";
                playbook.ForensicsGuidance = "Realizați un dump de memorie RAM înainte de oprirea stației pentru recuperarea eventualelor chei de decriptare din memorie.";

                playbook.Actions.Add(new CountermeasureAction
                {
                    Title = "🛡️ IZOLEAZĂ GAZDA DIN REȚEA (TAIERE TRAFIC)",
                    Description = "Blochează complet toate conexiunile de rețea de intrare și ieșire pentru a opri răspândirea ransomware-ului.",
                    ActionType = "Isolate",
                    PowerShellSnippet = "New-NetFirewallRule -DisplayName 'DFIR_EMERGENCY_ISOLATE' -Direction Inbound,Outbound -Action Block -Profile Any",
                    IsRecommended = true
                });

                playbook.Actions.Add(new CountermeasureAction
                {
                    Title = "🛑 Oprire Forțată Procese Suspecte & VssAdmin",
                    Description = "Termină procesele vssadmin, bcdedit și executabilele nesemnate din AppData/Temp.",
                    ActionType = "KillProcess",
                    PowerShellSnippet = "Get-Process | Where-Object { $_.Path -like '*AppData*' -or $_.Name -match 'vssadmin|bcdedit' } | Stop-Process -Force",
                    IsRecommended = true
                });
            }
            // 3. Furt Credențiale / Mimikatz / LSASS Dump (T1003)
            else if (titleLower.Contains("lsass") || titleLower.Contains("mimikatz") || tech.StartsWith("T1003"))
            {
                playbook.AttackCategory = "🚨 Tentativă Furt Credențiale (Mimikatz / LSASS)";
                playbook.ImmediateObjective = "Protejarea bazei de date de securitate SAM/LSA și resetarea imediată a conturilor administrative active pe stație.";
                playbook.ForensicsGuidance = "Activați Windows Defender Credential Guard (LSA Protection) prin registru pentru a preveni citirea directă a memoriei LSASS.";

                playbook.Actions.Add(new CountermeasureAction
                {
                    Title = "🛑 Oprește Procesul Atacator & Șterge Uneltele de Dump",
                    Description = "Termină procesul care a solicitat acces la memoria LSASS și curăță folderul din care a fost lansat.",
                    ActionType = "KillProcess",
                    PowerShellSnippet = "Get-Process | Where-Object { $_.Path -match 'mimikatz|procdump|sqldumper' } | Stop-Process -Force",
                    IsRecommended = true
                });

                playbook.Actions.Add(new CountermeasureAction
                {
                    Title = "🛡️ Activează Protecția LSA (RunAsPPL)",
                    Description = "Forțează pornirea LSASS ca Protected Process Light (PPL) pentru a bloca orice tentativă viitoare de injectare.",
                    ActionType = "Harden",
                    PowerShellSnippet = "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name 'RunAsPPL' -Value 1 -Type DWord",
                    IsRecommended = true
                });
            }
            // 4. Default / Generic Hacking Incident
            else
            {
                playbook.AttackCategory = "⚠️ Incident Cibernetic & Activitate Suspectă";
                playbook.ImmediateObjective = "Limitarea accesului atacatorului, colectarea artefactelor de memorie și blocarea persistenței.";
                playbook.ForensicsGuidance = "Verificați cheile de autorun din Registru (Run/RunOnce) și Task-urile programate (Scheduled Tasks).";

                playbook.Actions.Add(new CountermeasureAction
                {
                    Title = "🛡️ Izolează Gazda din Rețea",
                    Description = "Aplică profil de carantină pe adaptorul de rețea.",
                    ActionType = "Isolate",
                    PowerShellSnippet = "New-NetFirewallRule -DisplayName 'DFIR_Emergency_Isolation' -Direction Outbound -Action Block",
                    IsRecommended = true
                });

                playbook.Actions.Add(new CountermeasureAction
                {
                    Title = "🛑 Termină Procesele Copil Neautorizate",
                    Description = "Oprește procesele suspecte create în ultimele 5 minute.",
                    ActionType = "KillProcess",
                    PowerShellSnippet = "Stop-Process -Id [TargetPID] -Force",
                    IsRecommended = true
                });
            }

            return playbook;
        }

        private AttackerIntelligenceDetails ExtractDynamicAttackerIntel(DetectedIssue alert, string hostname)
        {
            var intel = new AttackerIntelligenceDetails();
            string rawContent = alert.Explanation ?? string.Empty;
            string userHost = $"{Environment.UserName} @ {hostname}";

            if (alert.RelatedEvents != null && alert.RelatedEvents.Count > 0)
            {
                var ev = alert.RelatedEvents[0];
                rawContent += " " + (ev.Message ?? string.Empty);
                if (!string.IsNullOrEmpty(ev.MachineName)) userHost = $"{Environment.UserName} @ {ev.MachineName}";
            }

            intel.TargetUserOrAccount = userHost;

            // 1. Extract URL or IP
            var urlMatch = Regex.Match(rawContent, @"https?://[a-zA-Z0-9\-\.]+(?::\d+)?(?:/[^\s""'>]*)?", RegexOptions.IgnoreCase);
            var ipMatch = Regex.Match(rawContent, @"\b(?:\d{1,3}\.){3}\d{1,3}\b");

            if (urlMatch.Success)
            {
                intel.SourceIpOrDomain = urlMatch.Value;
            }
            else if (ipMatch.Success)
            {
                intel.SourceIpOrDomain = $"IP: {ipMatch.Value} (Remote C2)";
            }
            else
            {
                intel.SourceIpOrDomain = "Local Process / Subrețea Internă (127.0.0.1 / SMB)";
            }

            // 2. Extract Process
            if (rawContent.Contains("vssadmin", StringComparison.OrdinalIgnoreCase)) intel.AttackProcessPath = "vssadmin.exe (Shadow Copy Deletion)";
            else if (rawContent.Contains("certutil", StringComparison.OrdinalIgnoreCase)) intel.AttackProcessPath = "certutil.exe (URL Cache Downloader)";
            else if (rawContent.Contains("powershell", StringComparison.OrdinalIgnoreCase)) intel.AttackProcessPath = "powershell.exe (ScriptBlock Execution)";
            else if (rawContent.Contains("mshta", StringComparison.OrdinalIgnoreCase)) intel.AttackProcessPath = "mshta.exe (HTML Application Host)";
            else if (rawContent.Contains("curl", StringComparison.OrdinalIgnoreCase)) intel.AttackProcessPath = "curl.exe (Web Payload Downloader)";
            else intel.AttackProcessPath = "cmd.exe / powershell.exe";

            // 3. Compute SHA256 of command
            using var sha = SHA256.Create();
            byte[] bytes = sha.ComputeHash(Encoding.UTF8.GetBytes(rawContent));
            intel.AttackHashSha256 = BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();

            // 4. Attribution based on technique
            string tech = (alert.MitreTechniqueId ?? string.Empty).ToUpperInvariant();
            if (tech.Contains("T1490") || rawContent.Contains("ransomware", StringComparison.OrdinalIgnoreCase))
            {
                intel.LikelyActorName = "LockBit 3.0 / BlackCat (ALPHV) Syndicate";
                intel.ActorCountryOrOrigin = "Grupare Cybercrime / Europa de Est";
                intel.Motivation = "Extorcare Financiară & Criptare Date";
                intel.KnownToolsUsed = "vssadmin, bcdedit, Cobalt Strike Beacon, PSExec";
                intel.DefenseRecommendation = "Izolare imediată a stației din rețea pentru protejarea share-urilor.";
            }
            else if (tech.Contains("T1566") || rawContent.Contains("phishing", StringComparison.OrdinalIgnoreCase))
            {
                intel.LikelyActorName = "Storm-0539 / TA558 (Cartel Phishing & Initial Access)";
                intel.ActorCountryOrOrigin = "Infrastructură Bulletproof / IP Proxy Olanda";
                intel.Motivation = "Furt de Credențiale / Sesiuni & Vânzare Acces Rețea";
                intel.KnownToolsUsed = "CertUtil LOLBAS, HTA Stager, Evilginx, PowerShell WebRequest";
                intel.DefenseRecommendation = "Blocare URL pe firewall și resetare forțată a token-urilor.";
            }
            else if (tech.Contains("T1003") || rawContent.Contains("lsass", StringComparison.OrdinalIgnoreCase))
            {
                intel.LikelyActorName = "APT28 (Fancy Bear) / Lazarus Group";
                intel.ActorCountryOrOrigin = "Actor Statal / Advanced Persistent Threat (APT)";
                intel.Motivation = "Spionaj Cibernetic & Escaladare Privilegii Administrative";
                intel.KnownToolsUsed = "Mimikatz, Procdump, Sekurlsa, Nanodump";
                intel.DefenseRecommendation = "Activare LSA Protection (RunAsPPL) și resetare conturi administrative.";
            }
            else
            {
                intel.LikelyActorName = "Actor Cibernetic Necunoscut / Script Automatizat";
                intel.ActorCountryOrOrigin = "Infrastructură Externă Anonimizată";
                intel.Motivation = "Reconnoaștere & Escaladare Privilegii";
                intel.KnownToolsUsed = "Living-off-the-Land (LOLBAS)";
                intel.DefenseRecommendation = "Inspectare procese active și blocare porturi neutilizate.";
            }

            return intel;
        }
    }
}
