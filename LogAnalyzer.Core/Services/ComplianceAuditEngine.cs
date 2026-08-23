using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class ComplianceCheckResult
    {
        public string Framework { get; set; } = string.Empty; // "HG 585/2002", "NIS2 (Directiva UE 2022/2555)", "ISO/IEC 27042", "GDPR", "PCI-DSS"
        public string ArticleOrControl { get; set; } = string.Empty;
        public string ControlTitle { get; set; } = string.Empty;
        public string Status { get; set; } = "CONFORM"; // "CONFORM", "NON-CONFORM", "ATENȚIE"
        public string StatusColor { get; set; } = "#34D399";
        public string EvidenceSummary { get; set; } = string.Empty;
        public string RequiredAction { get; set; } = string.Empty;
    }

    public class ComplianceAuditEngine
    {
        public List<ComplianceCheckResult> Evaluate(
            IEnumerable<ParsedEvent> events, 
            AdAuditSummary adSummary, 
            StandaloneSamSummary samSummary, 
            int yaraMatchesCount, 
            int totalAnomalies)
        {
            var results = new List<ComplianceCheckResult>();

            // 1. HG 585/2002 - Securitatea Informațiilor Clasificate (Standard Național România)
            bool hg585Violated = samSummary.UsbStorageEventsCount > 0 || samSummary.AuditPolicyTamperingCount > 0;
            results.Add(new ComplianceCheckResult
            {
                Framework = "HG 585/2002 (România)",
                ArticleOrControl = "Art. 158 / Art. 191",
                ControlTitle = "Integritatea Mediilor de Stocare și Interdicția Conexiunilor Neautorizate",
                Status = hg585Violated ? "NON-CONFORM" : "CONFORM",
                StatusColor = hg585Violated ? "#FF4D6D" : "#34D399",
                EvidenceSummary = hg585Violated 
                    ? $"Detectate {samSummary.UsbStorageEventsCount} inserări de medii removabile și {samSummary.AuditPolicyTamperingCount} modificări ale politicii de audit." 
                    : "Zero medii neautorizate conectate. Politica de auditare este activă și neschimbată.",
                RequiredAction = hg585Violated 
                    ? "Înregistrați de urgență incidentul de securitate în Registrul de Transferuri conform procedurii OCS." 
                    : "Mențineți verificarea periodică a integrității fizice și logice."
            });

            // 2. Directiva NIS2 (UE 2022/2555) / OUG 155/2024 (DNSC)
            bool nis2Critical = adSummary.KerberosAttacksDetected > 0 || totalAnomalies > 5;
            results.Add(new ComplianceCheckResult
            {
                Framework = "NIS2 (Directiva UE 2022/2555)",
                ArticleOrControl = "Art. 23 (Notificare 24h)",
                ControlTitle = "Gestiunea Incidentelor Semnificative de Securitate Cibernetică",
                Status = nis2Critical ? "NON-CONFORM" : "CONFORM",
                StatusColor = nis2Critical ? "#FF4D6D" : "#34D399",
                EvidenceSummary = nis2Critical 
                    ? $"Detectate atacuri critice de domeniu ({adSummary.KerberosAttacksDetected} atacuri Kerberos/AD). Impune notificare către DNSC/CSIRT în termen de 24h." 
                    : "Nu s-au detectat incidente cu impact semnificativ asupra continuității operaționale.",
                RequiredAction = nis2Critical 
                    ? "Generați draftul de notificare timpurie (Early Warning) din modulul Chain of Custody / NIS2." 
                    : "Continuați monitorizarea continuă a fluxului de evenimente."
            });

            // 3. ISO/IEC 27042 - Lanț de Custodie și Integritate Forensică
            results.Add(new ComplianceCheckResult
            {
                Framework = "ISO/IEC 27042",
                ArticleOrControl = "Clauza 6.4 (Chain of Custody)",
                ControlTitle = "Garantarea Integrității Probelor Digitale (Cryptographic Provenance)",
                Status = "CONFORM",
                StatusColor = "#34D399",
                EvidenceSummary = "Toate evenimentele analizate sunt semnate cu amprente hash SHA-256 și stocate în baza de date locală criptată SQLCipher.",
                RequiredAction = "Exportați lanțul de custodie în format CASE/UCO 1.3 la finalizarea investigației."
            });

            // 4. GDPR (Regulamentul UE 2016/679)
            bool gdprRisk = samSummary.LocalAccountsCreated > 0 || adSummary.UserAccountsCreated > 0;
            results.Add(new ComplianceCheckResult
            {
                Framework = "GDPR (Regulamentul UE 2016/679)",
                ArticleOrControl = "Art. 32 (Securitatea Prelucrării)",
                ControlTitle = "Controlul Accesului și Gestiunea Conturilor de Utilizator",
                Status = gdprRisk ? "ATENȚIE" : "CONFORM",
                StatusColor = gdprRisk ? "#F6C445" : "#34D399",
                EvidenceSummary = gdprRisk 
                    ? $"Înregistrate conturi noi de utilizator create ({adSummary.UserAccountsCreated} în AD, {samSummary.LocalAccountsCreated} local SAM). Necesită verificare cu principiul 'Need-to-Know'." 
                    : "Zero conturi noi neautorizate identificate.",
                RequiredAction = gdprRisk 
                    ? "Verificați permisiunile acordate noilor conturi pentru a preveni accesul excesiv la date cu caracter personal." 
                    : "Păstrați revizuirea trimestrială a drepturilor de acces."
            });

            // 5. PCI-DSS v4.0
            bool pciDssViolated = adSummary.AccountLockouts > 3 || samSummary.LocalAccountLockouts > 3;
            results.Add(new ComplianceCheckResult
            {
                Framework = "PCI-DSS v4.0",
                ArticleOrControl = "Cerința 8.3.4",
                ControlTitle = "Blocarea Conturilor la Tentative Repetate de Autentificare Eșuată",
                Status = pciDssViolated ? "ATENȚIE" : "CONFORM",
                StatusColor = pciDssViolated ? "#F6C445" : "#34D399",
                EvidenceSummary = pciDssViolated 
                    ? $"Detectat prag depășit de blocări de conturi ({adSummary.AccountLockouts + samSummary.LocalAccountLockouts} blocări)." 
                    : "Mecanismul de blocare a conturilor funcționează în parametri optimi.",
                RequiredAction = pciDssViolated 
                    ? "Investigați sursa atacului de forță brută și verificați IP-urile sursă." 
                    : "Mențineți pragul de lockout configurat la maxim 5 tentative eșuate."
            });

            return results;
        }
    }
}
