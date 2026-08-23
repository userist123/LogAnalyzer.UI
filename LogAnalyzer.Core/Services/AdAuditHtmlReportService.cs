using System;
using System.Collections.Generic;
using System.Text;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class AdAuditHtmlReportService
    {
        public string GenerateHtmlReport(
            AdAuditSummary adSummary,
            StandaloneSamSummary samSummary,
            IEnumerable<KerberosAdFinding> findings,
            IEnumerable<StandaloneSamFinding> samFindings,
            IEnumerable<UbaAnomalyItem> ubaAnomalies,
            IEnumerable<ComplianceCheckResult> complianceResults)
        {
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html lang=\"ro\">");
            sb.AppendLine("<head>");
            sb.AppendLine("<meta charset=\"utf-8\"/>");
            sb.AppendLine("<title>ADAudit Plus & DFIR Executive Security Report</title>");
            sb.AppendLine("<style>");
            sb.AppendLine("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI Variable Display', 'Segoe UI', Roboto, sans-serif; background-color: #080B12; color: #F1F5F9; margin: 0; padding: 32px; }");
            sb.AppendLine(".header { border-bottom: 2px solid #232E42; padding-bottom: 20px; margin-bottom: 28px; }");
            sb.AppendLine(".title { font-size: 26px; font-weight: 700; color: #6EA8FE; margin: 0; }");
            sb.AppendLine(".subtitle { font-size: 13px; color: #A8B5C7; margin-top: 6px; }");
            sb.AppendLine(".kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 32px; }");
            sb.AppendLine(".card { background: #111827; border: 1px solid #232E42; border-radius: 8px; padding: 18px; }");
            sb.AppendLine(".card-val { font-size: 28px; font-weight: 800; color: #F1F5F9; margin: 6px 0; }");
            sb.AppendLine(".card-lbl { font-size: 11px; text-transform: uppercase; font-weight: 700; color: #718096; }");
            sb.AppendLine("h2 { font-size: 18px; border-left: 4px solid #6EA8FE; padding-left: 10px; margin-top: 36px; margin-bottom: 16px; }");
            sb.AppendLine("table { width: 100%; border-collapse: collapse; margin-bottom: 28px; background: #0C111B; border: 1px solid #232E42; border-radius: 6px; overflow: hidden; font-size: 12.5px; }");
            sb.AppendLine("th { background: #151E2E; color: #A8B5C7; text-align: left; padding: 12px 14px; font-weight: 600; border-bottom: 1px solid #232E42; }");
            sb.AppendLine("td { padding: 10px 14px; border-bottom: 1px solid rgba(148,163,184,0.08); color: #F1F5F9; }");
            sb.AppendLine(".badge-crit { background: rgba(255,77,109,0.2); color: #FF4D6D; padding: 3px 8px; border-radius: 4px; font-weight: 700; }");
            sb.AppendLine(".badge-ok { background: rgba(52,211,153,0.2); color: #34D399; padding: 3px 8px; border-radius: 4px; font-weight: 700; }");
            sb.AppendLine(".footer { margin-top: 48px; border-top: 1px solid #232E42; padding-top: 16px; font-size: 11px; color: #718096; text-align: center; }");
            sb.AppendLine("</style>");
            sb.AppendLine("</head>");
            sb.AppendLine("<body>");

            sb.AppendLine("<div class=\"header\">");
            sb.AppendLine("<h1 class=\"title\">ADAUDIT PLUS &amp; FORENSIC INTELLIGENCE SUITE</h1>");
            sb.AppendLine($"<div class=\"subtitle\">Raport Executiv de Securitate Active Directory, Endpoint SAM și Conformitate Reglementară | Generat la {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</div>");
            sb.AppendLine("</div>");

            // KPI Grid
            sb.AppendLine("<div class=\"kpi-grid\">");
            sb.AppendLine($"<div class=\"card\"><div class=\"card-lbl\">Evenimente AD Auditate</div><div class=\"card-val\">{adSummary.TotalAdEventsAnalyzed}</div></div>");
            sb.AppendLine($"<div class=\"card\"><div class=\"card-lbl\">Grupuri Privilegiate AD</div><div class=\"card-val\" style=\"color:#FF4D6D;\">{adSummary.PrivilegedGroupChanges}</div></div>");
            sb.AppendLine($"<div class=\"card\"><div class=\"card-lbl\">Admini Locali SAM</div><div class=\"card-val\" style=\"color:#FF4D6D;\">{samSummary.LocalAdminGroupModifications}</div></div>");
            sb.AppendLine($"<div class=\"card\"><div class=\"card-lbl\">Medii USB Conectate</div><div class=\"card-val\" style=\"color:#FF7A45;\">{samSummary.UsbStorageEventsCount}</div></div>");
            sb.AppendLine($"<div class=\"card\"><div class=\"card-lbl\">Alterare Politici GPO/SAM</div><div class=\"card-val\" style=\"color:#F6C445;\">{adSummary.GpoPolicyChanges + samSummary.AuditPolicyTamperingCount}</div></div>");
            sb.AppendLine($"<div class=\"card\"><div class=\"card-lbl\">Atacuri Kerberos / AD</div><div class=\"card-val\" style=\"color:#6EA8FE;\">{adSummary.KerberosAttacksDetected}</div></div>");
            sb.AppendLine("</div>");

            // 1. AD Attack Findings
            sb.AppendLine("<h2>1. Detecții Atacuri Active Directory &amp; Kerberos (Domain Level)</h2>");
            sb.AppendLine("<table>");
            sb.AppendLine("<tr><th>Categorie</th><th>Tip Atac</th><th>Severitate</th><th>Cont Țintă</th><th>MITRE</th><th>Descriere &amp; Acțiune</th></tr>");
            if (findings != null)
            {
                foreach (var f in findings)
                {
                    sb.AppendLine($"<tr><td>{f.Category}</td><td><strong>{f.AttackType}</strong></td><td><span class=\"badge-crit\">{f.Severity}</span></td><td>{f.TargetAccount}</td><td>{f.MitreTechniqueId}</td><td>{f.Description}</td></tr>");
                }
            }
            sb.AppendLine("</table>");

            // 2. Standalone SAM Findings
            sb.AppendLine("<h2>2. Detecții Securitate Stație Standalone &amp; SAM Local</h2>");
            sb.AppendLine("<table>");
            sb.AppendLine("<tr><th>Categorie</th><th>Tip Detecție</th><th>Severitate</th><th>Resursă Țintă</th><th>MITRE</th><th>Acțiune Recomandată</th></tr>");
            if (samFindings != null)
            {
                foreach (var sf in samFindings)
                {
                    sb.AppendLine($"<tr><td>{sf.Category}</td><td><strong>{sf.FindingType}</strong></td><td><span class=\"badge-crit\">{sf.Severity}</span></td><td>{sf.TargetAccountOrResource}</td><td>{sf.MitreTechniqueId}</td><td>{sf.RemediationActionRo}</td></tr>");
                }
            }
            sb.AppendLine("</table>");

            // 3. Compliance Matrix
            sb.AppendLine("<h2>3. Matrice de Evaluare a Conformității (HG 585/2002, NIS2, ISO 27042, GDPR)</h2>");
            sb.AppendLine("<table>");
            sb.AppendLine("<tr><th>Cadru</th><th>Articol</th><th>Titlu Control</th><th>Status</th><th>Evidență Forensică</th><th>Măsură Impusă</th></tr>");
            if (complianceResults != null)
            {
                foreach (var cr in complianceResults)
                {
                    string badge = cr.Status == "CONFORM" ? "badge-ok" : "badge-crit";
                    sb.AppendLine($"<tr><td>{cr.Framework}</td><td>{cr.ArticleOrControl}</td><td><strong>{cr.ControlTitle}</strong></td><td><span class=\"{badge}\">{cr.Status}</span></td><td>{cr.EvidenceSummary}</td><td>{cr.RequiredAction}</td></tr>");
                }
            }
            sb.AppendLine("</table>");

            sb.AppendLine("<div class=\"footer\">LogAnalyzer Enterprise — Threat Operations &amp; ADAudit Plus Suite | All rights reserved</div>");
            sb.AppendLine("</body>");
            sb.AppendLine("</html>");

            return sb.ToString();
        }
    }
}
