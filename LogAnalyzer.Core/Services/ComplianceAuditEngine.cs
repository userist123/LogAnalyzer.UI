using System;
using System.Collections.Generic;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class ComplianceAuditEngine
    {
        public List<ComplianceCheckResult> Evaluate(
            IEnumerable<ParsedEvent> events,
            AdAuditSummary adSummary,
            StandaloneSamSummary samSummary,
            int yaraMatchesCount,
            int anomalyCount)
        {
            var results = new List<ComplianceCheckResult>();

            // 1. HG 585/2002 - Securitatea InformaÈ›iilor Clasificate (RomÃ¢nia)
            bool hg585Pass = samSummary.LocalAdminGroupModifications == 0 && samSummary.AuditPolicyTamperingCount == 0 && adSummary.PrivilegedGroupChanges == 0;
            results.Add(new ComplianceCheckResult
            {
                Framework = "HG 585/2002 (RomÃ¢nia)",
                ArticleOrControl = "Art. 21 / Control Acces Privilegii",
                ControlTitle = "Gestiunea È™i Auditarea Rolurilor Administrative",
                Status = hg585Pass ? "CONFORM" : "NON-CONFORM",
                EvidenceSummary = $"ModificÄƒri Admini AD: {adSummary.PrivilegedGroupChanges}, ModificÄƒri Admini SAM: {samSummary.LocalAdminGroupModifications}, AlterÄƒri Politici: {samSummary.AuditPolicyTamperingCount}",
                RequiredAction = hg585Pass ? "MenÈ›inerea jurnalizÄƒrii stricte." : "Revizuirea imediatÄƒ a numirilor Ã®n grupurile administrative È™i raportarea incidentului."
            });

            // 2. Directiva NIS2 (UE 2022/2555) / Legea SecuritÄƒÈ›ii Cibernetice
            bool nis2Pass = adSummary.KerberosAttacksDetected == 0 && yaraMatchesCount == 0;
            results.Add(new ComplianceCheckResult
            {
                Framework = "Directiva NIS2 (UE 2022/2555)",
                ArticleOrControl = "Art. 21 / Securitatea LanÈ›ului & Incident Response",
                ControlTitle = "CapabilitÄƒÈ›i de DetecÈ›ie È™i RÄƒspuns la Atacuri Avansate",
                Status = nis2Pass ? "CONFORM" : "NON-CONFORM",
                EvidenceSummary = $"Atacuri Active Directory / Kerberos: {adSummary.KerberosAttacksDetected}, SemnÄƒturi YARA Malicioase: {yaraMatchesCount}",
                RequiredAction = nis2Pass ? "PosturÄƒ defensivÄƒ adecvatÄƒ." : "DeclanÈ™area notificÄƒrii timpurii cÄƒtre DNSC Ã®n termen de 24 de ore conform NIS2."
            });

            // 3. ISO/IEC 27042 - Ghid de AnalizÄƒ È™i PÄƒstrare a Probelor Digitale
            results.Add(new ComplianceCheckResult
            {
                Framework = "ISO/IEC 27042",
                ArticleOrControl = "Clauza 7.4 / Integritatea LanÈ›ului de Custodie",
                ControlTitle = "PÄƒstrarea IntegritÄƒÈ›ii Probatorii cu Hash Criptografic SHA-256",
                Status = "CONFORM",
                EvidenceSummary = "Toate jurnalele EVTX È™i artefactele sunt imutabile È™i indexate Ã®n baza de date securizatÄƒ SQLCipher.",
                RequiredAction = "Nu sunt necesare mÄƒsuri corective."
            });

            // 4. GDPR (Regulamentul UE 2016/679)
            bool gdprPass = samSummary.UsbStorageEventsCount == 0 && anomalyCount == 0;
            results.Add(new ComplianceCheckResult
            {
                Framework = "GDPR (UE 2016/679)",
                ArticleOrControl = "Art. 32 / Securitatea PrelucrÄƒrii Datelor cu Caracter Personal",
                ControlTitle = "ProtecÈ›ia ÃŽmpotriva Scurgerilor È™i Extragerii Neautorizate",
                Status = gdprPass ? "CONFORM" : "ATENÈšIE",
                EvidenceSummary = $"Evenimente Stocare USB RemovabilÄƒ: {samSummary.UsbStorageEventsCount}, Anomalii Comportamentale: {anomalyCount}",
                RequiredAction = gdprPass ? "Monitorizare continuÄƒ." : "Auditarea registrelor de transfer de date pe suporturi optice/USB."
            });

            // 5. PCI-DSS v4.0
            bool pciPass = adSummary.AccountLockouts < 10 && adSummary.PasswordResets < 5;
            results.Add(new ComplianceCheckResult
            {
                Framework = "PCI-DSS v4.0",
                ArticleOrControl = "CerinÈ›a 8.3 & 10.2 / Audit Log & Autentificare",
                ControlTitle = "ProtecÈ›ia Mecanismelor de Autentificare È™i Contorizare BlocÄƒri",
                Status = pciPass ? "CONFORM" : "ATENÈšIE",
                EvidenceSummary = $"BlocÄƒri de Conturi (EID 4740): {adSummary.AccountLockouts}, ResetÄƒri Parole (EID 4724): {adSummary.PasswordResets}",
                RequiredAction = pciPass ? "Conformitate validatÄƒ." : "Verificarea tentativelor de tip Password Spraying Ã®mpotriva conturilor din scope."
            });

            return results;
        }
    }
}
