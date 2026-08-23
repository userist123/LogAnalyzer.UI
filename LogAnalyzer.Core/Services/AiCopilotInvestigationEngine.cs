using System;
using System.Collections.Generic;
using System.Text;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class CopilotInvestigationResult
    {
        public string Title { get; set; } = string.Empty;
        public string ExecutiveSummaryRo { get; set; } = string.Empty;
        public string MitreKillChainMapping { get; set; } = string.Empty;
        public string RiskLevel { get; set; } = "High";
        public List<string> ForensicEvidenceBullets { get; set; } = new();
        public List<string> RecommendedContainmentSteps { get; set; } = new();
        public string RegulatoryImpactRo { get; set; } = string.Empty;
        public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;
    }

    public class AiCopilotInvestigationEngine
    {
        public CopilotInvestigationResult InvestigateFinding(string findingType, string category, string target, string description, string mitreId)
        {
            var result = new CopilotInvestigationResult
            {
                Title = $"Investigație Asistată AI: {findingType}",
                GeneratedAt = DateTime.UtcNow
            };

            var evidence = new List<string>();
            var steps = new List<string>();

            if (category.Contains("Kerberos", StringComparison.OrdinalIgnoreCase) || findingType.Contains("Kerberoasting", StringComparison.OrdinalIgnoreCase))
            {
                result.RiskLevel = "Critic";
                result.ExecutiveSummaryRo = $"Detectată tentativă activă de Kerberoasting (T1558.003) împotriva contului de serviciu '{target}'. Atacatorul solicită tichete TGS cu criptare slabă (RC4-HMAC) pentru a sparge offline parola contului.";
                result.MitreKillChainMapping = "Credential Access -> T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)";
                result.RegulatoryImpactRo = "Conform HG 585/2002 Art. 21 și NIS2 Art. 21, compromiterea unui cont de serviciu de domeniu constituie incident de securitate major ce impune notificare DNSC în 24 de ore.";

                evidence.Add($"Cont țintă: {target}");
                evidence.Add("Tip solicitare: Kerberos TGS Ticket cu cifru 0x17 (RC4)");
                evidence.Add($"Descriere: {description}");

                steps.Add("1. Rotiți imediat parola contului de serviciu și setați o lungime de minim 25 caractere aleatorii.");
                steps.Add("2. Forțați tipul de criptare AES-256 pentru SPN-ul asociat (Set-ADUser -KerberosEncryptionType AES128,AES256).");
                steps.Add("3. Auditați stația sursă de unde a fost emisă cererea TGS pentru identificarea procesului compromis.");
            }
            else if (category.Contains("SAM", StringComparison.OrdinalIgnoreCase) || findingType.Contains("Administrators", StringComparison.OrdinalIgnoreCase))
            {
                result.RiskLevel = "Critic";
                result.ExecutiveSummaryRo = $"Detectată escaladare de privilegii la nivel local prin adăugarea neautorizată a unui cont în grupul 'BUILTIN\\Administrators' pe stația standalone '{target}'.";
                result.MitreKillChainMapping = "Persistence & Privilege Escalation -> T1078.003 (Local Accounts) & T1098 (Account Manipulation)";
                result.RegulatoryImpactRo = "Conform standardului ISO/IEC 27042 și politicilor de clasificare, acordarea drepturilor administrative pe stații de lucru izolate necesită ordin de serviciu scris.";

                evidence.Add($"Resursă afectată: {target}");
                evidence.Add($"Descriere tehnică: {description}");
                evidence.Add($"Tehnică MITRE: {mitreId}");

                steps.Add("1. Eliminați imediat contul din grupul local de administratori (Remove-LocalGroupMember -Group Administrators).");
                steps.Add("2. Dezactivați temporar contul adăugat până la finalizarea investigației forensice.");
                steps.Add("3. Extrageți jurnalele de securitate EVTX și artefactele Registry (Shimcache, UserAssist) de pe stație.");
            }
            else if (category.Contains("File", StringComparison.OrdinalIgnoreCase) || findingType.Contains("Ransomware", StringComparison.OrdinalIgnoreCase))
            {
                result.RiskLevel = "Critic";
                result.ExecutiveSummaryRo = $"Identificat comportament specific atacurilor de tip Ransomware pe partajarea de fișiere '{target}'. Au fost detectate operațiuni masive de redenumire și scriere rapidă de fișiere.";
                result.MitreKillChainMapping = "Impact -> T1486 (Data Encrypted for Impact)";
                result.RegulatoryImpactRo = "Directiva NIS2 (UE 2022/2555) impune izolarea imediată a sistemelor afectate și raportare incident în termen de maxim 24 ore la autoritatea națională (DNSC).";

                evidence.Add($"Partajare afectată: {target}");
                evidence.Add("Semnătură: Extensii de fișiere suspecte (.locked / .crypto) și rată ridicată de I/O");
                evidence.Add($"Diagnostic: {description}");

                steps.Add("1. Opriți imediat serviciul LanmanServer pe file server pentru a stopa criptarea prin rețea.");
                steps.Add("2. Identificați adresa IP a stației client SMB compromise și deconectați-o fizic din switch.");
                steps.Add("3. Păstrați snapshot-urile VSS curente și începeți restaurarea din backup-ul imutabil offline.");
            }
            else
            {
                result.RiskLevel = "Ridicat";
                result.ExecutiveSummaryRo = $"Analiza automată a identificat o anomalie de securitate: '{findingType}' asociată cu '{target}'.";
                result.MitreKillChainMapping = $"Tactici & Tehnici MITRE ATT&CK: {mitreId}";
                result.RegulatoryImpactRo = "Evaluare conform cerințelor de auditare a jurnalelor de evenimente HG 585/2002.";

                evidence.Add($"Entitate diagnosticată: {target}");
                evidence.Add($"Descriere: {description}");

                steps.Add("1. Inspectați istoricul de evenimente corelate pentru această entitate în Event Explorer.");
                steps.Add("2. Verificați dacă activitatea a fost autorizată prin procedurile standard de operare (SOP).");
            }

            result.ForensicEvidenceBullets = evidence;
            result.RecommendedContainmentSteps = steps;
            return result;
        }
    }
}
