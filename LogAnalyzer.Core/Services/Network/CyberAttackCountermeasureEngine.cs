using System;
using System.Collections.Generic;
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

    public class CountermeasurePlaybook
    {
        public string AttackCategory { get; set; } = string.Empty;
        public string ThreatLevel { get; set; } = "Critical";
        public string ImmediateObjective { get; set; } = string.Empty;
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
                ThreatLevel = alert.Severity
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
    }
}
