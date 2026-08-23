using System;
using System.Collections.Generic;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class AiCopilotInvestigationEngine
    {
        public CopilotInvestigationResult InvestigateFinding(string findingType, string category, string target, string description, string mitreId)
        {
            var result = new CopilotInvestigationResult
            {
                Title = $"InvestigaÈ›ie AsistatÄƒ AI: {findingType}",
                GeneratedAt = DateTime.UtcNow
            };

            var evidence = new List<string>();
            var steps = new List<string>();

            if (category.Contains("Kerberos", StringComparison.OrdinalIgnoreCase) || findingType.Contains("Kerberoasting", StringComparison.OrdinalIgnoreCase))
            {
                result.RiskLevel = "Critic";
                result.ExecutiveSummaryRo = $"DetectatÄƒ tentativÄƒ activÄƒ de Kerberoasting (T1558.003) Ã®mpotriva contului de serviciu '{target}'. Atacatorul solicitÄƒ tichete TGS cu criptare slabÄƒ (RC4-HMAC) pentru a sparge offline parola contului.";
                result.MitreKillChainMapping = "Credential Access -> T1558.003 (Steal or Forge Kerberos Tickets: Kerberoasting)";
                result.RegulatoryImpactRo = "Conform HG 585/2002 Art. 21 È™i NIS2 Art. 21, compromiterea unui cont de serviciu de domeniu constituie incident de securitate major ce impune notificare DNSC Ã®n 24 de ore.";

                evidence.Add($"Cont È›intÄƒ: {target}");
                evidence.Add("Tip solicitare: Kerberos TGS Ticket cu cifru 0x17 (RC4)");
                evidence.Add($"Descriere: {description}");

                steps.Add("1. RotiÈ›i imediat parola contului de serviciu È™i setaÈ›i o lungime de minim 25 caractere aleatorii.");
                steps.Add("2. ForÈ›aÈ›i tipul de criptare AES-256 pentru SPN-ul asociat (Set-ADUser -KerberosEncryptionType AES128,AES256).");
                steps.Add("3. AuditaÈ›i staÈ›ia sursÄƒ de unde a fost emisÄƒ cererea TGS pentru identificarea procesului compromis.");
            }
            else if (category.Contains("SAM", StringComparison.OrdinalIgnoreCase) || findingType.Contains("Administrators", StringComparison.OrdinalIgnoreCase))
            {
                result.RiskLevel = "Critic";
                result.ExecutiveSummaryRo = $"DetectatÄƒ escaladare de privilegii la nivel local prin adÄƒugarea neautorizatÄƒ a unui cont Ã®n grupul 'BUILTIN\\Administrators' pe staÈ›ia standalone '{target}'.";
                result.MitreKillChainMapping = "Persistence & Privilege Escalation -> T1078.003 (Local Accounts) & T1098 (Account Manipulation)";
                result.RegulatoryImpactRo = "Conform standardului ISO/IEC 27042 È™i politicilor de clasificare, acordarea drepturilor administrative pe staÈ›ii de lucru izolate necesitÄƒ ordin de serviciu scris.";

                evidence.Add($"ResursÄƒ afectatÄƒ: {target}");
                evidence.Add($"Descriere tehnicÄƒ: {description}");
                evidence.Add($"TehnicÄƒ MITRE: {mitreId}");

                steps.Add("1. EliminaÈ›i imediat contul din grupul local de administratori (Remove-LocalGroupMember -Group Administrators).");
                steps.Add("2. DezactivaÈ›i temporar contul adÄƒugat pÃ¢nÄƒ la finalizarea investigaÈ›iei forensice.");
                steps.Add("3. ExtrageÈ›i jurnalele de securitate EVTX È™i artefactele Registry (Shimcache, UserAssist) de pe staÈ›ie.");
            }
            else if (category.Contains("File", StringComparison.OrdinalIgnoreCase) || findingType.Contains("Ransomware", StringComparison.OrdinalIgnoreCase))
            {
                result.RiskLevel = "Critic";
                result.ExecutiveSummaryRo = $"Identificat comportament specific atacurilor de tip Ransomware pe partajarea de fiÈ™iere '{target}'. Au fost detectate operaÈ›iuni masive de redenumire È™i scriere rapidÄƒ de fiÈ™iere.";
                result.MitreKillChainMapping = "Impact -> T1486 (Data Encrypted for Impact)";
                result.RegulatoryImpactRo = "Directiva NIS2 (UE 2022/2555) impune izolarea imediatÄƒ a sistemelor afectate È™i raportare incident Ã®n termen de maxim 24 ore la autoritatea naÈ›ionalÄƒ (DNSC).";

                evidence.Add($"Partajare afectatÄƒ: {target}");
                evidence.Add("SemnÄƒturÄƒ: Extensii de fiÈ™iere suspecte (.locked / .crypto) È™i ratÄƒ ridicatÄƒ de I/O");
                evidence.Add($"Diagnostic: {description}");

                steps.Add("1. OpriÈ›i imediat serviciul LanmanServer pe file server pentru a stopa criptarea prin reÈ›ea.");
                steps.Add("2. IdentificaÈ›i adresa IP a staÈ›iei client SMB compromise È™i deconectaÈ›i-o fizic din switch.");
                steps.Add("3. PÄƒstraÈ›i snapshot-urile VSS curente È™i Ã®ncepeÈ›i restaurarea din backup-ul imutabil offline.");
            }
            else
            {
                result.RiskLevel = "Ridicat";
                result.ExecutiveSummaryRo = $"Analiza automatÄƒ a identificat o anomalie de securitate: '{findingType}' asociatÄƒ cu '{target}'.";
                result.MitreKillChainMapping = $"Tactici & Tehnici MITRE ATT&CK: {mitreId}";
                result.RegulatoryImpactRo = "Evaluare conform cerinÈ›elor de auditare a jurnalelor de evenimente HG 585/2002.";

                evidence.Add($"Entitate diagnosticatÄƒ: {target}");
                evidence.Add($"Descriere: {description}");

                steps.Add("1. InspectaÈ›i istoricul de evenimente corelate pentru aceastÄƒ entitate Ã®n Event Explorer.");
                steps.Add("2. VerificaÈ›i dacÄƒ activitatea a fost autorizatÄƒ prin procedurile standard de operare (SOP).");
            }

            result.ForensicEvidenceBullets = evidence;
            result.RecommendedContainmentSteps = steps;
            return result;
        }
    }
}
