using System;
using System.Collections.Generic;
using System.Linq;
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
            IEnumerable<ComplianceCheckResult> complianceResults,
            bool isAirGapped = true)
        {
            var sb = new StringBuilder();
            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html lang=\"ro\">");
            sb.AppendLine("<head>");
            sb.AppendLine("<meta charset=\"utf-8\"/>");
            sb.AppendLine("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"/>");
            
            string title = isAirGapped ? "Raport Securitate & Audit Forensic Stație Standalone (HG 585 / ISO 27042)" : "Raport Executiv Securitate Active Directory & Enterprise SOC";
            sb.AppendLine($"<title>{title}</title>");
            sb.AppendLine("<style>");
            sb.AppendLine("body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0A0E17; color: #E2E8F0; margin: 0; padding: 32px; line-height: 1.5; }");
            sb.AppendLine(".container { max-width: 1200px; margin: 0 auto; }");
            sb.AppendLine(".header { border-bottom: 2px solid #1E293B; padding-bottom: 20px; margin-bottom: 28px; display: flex; justify-content: space-between; align-items: flex-end; }");
            sb.AppendLine(".title { font-size: 24px; font-weight: 800; color: #38BDF8; margin: 0; }");
            sb.AppendLine(".subtitle { font-size: 13px; color: #94A3B8; margin-top: 6px; }");
            sb.AppendLine(".badge-mode { background: #1E293B; border: 1px solid #38BDF8; color: #38BDF8; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }");
            sb.AppendLine(".kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 32px; }");
            sb.AppendLine(".card { background: #111827; border: 1px solid #1E293B; border-radius: 8px; padding: 16px; }");
            sb.AppendLine(".card-val { font-size: 26px; font-weight: 800; color: #F8FAFC; margin: 4px 0; }");
            sb.AppendLine(".card-lbl { font-size: 10.5px; text-transform: uppercase; font-weight: 700; color: #64748B; }");
            sb.AppendLine("h2 { font-size: 16px; font-weight: 700; border-left: 4px solid #38BDF8; padding-left: 10px; margin-top: 36px; margin-bottom: 14px; color: #F1F5F9; }");
            sb.AppendLine("table { width: 100%; border-collapse: collapse; margin-bottom: 24px; background: #0F172A; border: 1px solid #1E293B; border-radius: 6px; overflow: hidden; font-size: 12px; }");
            sb.AppendLine("th { background: #1E293B; color: #94A3B8; text-align: left; padding: 10px 12px; font-weight: 600; border-bottom: 1px solid #334155; }");
            sb.AppendLine("td { padding: 9px 12px; border-bottom: 1px solid rgba(148,163,184,0.08); color: #E2E8F0; vertical-align: top; }");
            sb.AppendLine(".badge-crit { background: rgba(239,68,68,0.2); color: #EF4444; padding: 2px 6px; border-radius: 4px; font-weight: 700; font-size: 11px; }");
            sb.AppendLine(".badge-warn { background: rgba(245,158,11,0.2); color: #F59E0B; padding: 2px 6px; border-radius: 4px; font-weight: 700; font-size: 11px; }");
            sb.AppendLine(".badge-ok { background: rgba(16,185,129,0.2); color: #10B981; padding: 2px 6px; border-radius: 4px; font-weight: 700; font-size: 11px; }");
            sb.AppendLine(".empty-row { text-align: center; color: #64748B; font-style: italic; padding: 18px !important; }");
            sb.AppendLine(".footer { margin-top: 48px; border-top: 1px solid #1E293B; padding-top: 16px; font-size: 11px; color: #64748B; text-align: center; }");
            sb.AppendLine("</style>");
            sb.AppendLine("</head>");
            sb.AppendLine("<body>");
            sb.AppendLine("<div class=\"container\">");

            // Header
            sb.AppendLine("<div class=\"header\">");
            sb.AppendLine("<div>");
            sb.AppendLine($"<h1 class=\"title\">{(isAirGapped ? "STANDALONE ENDPOINT FORENSICS &amp; SAM AUDIT" : "ACTIVE DIRECTORY &amp; ENTERPRISE ADAUDIT 360")}</h1>");
            sb.AppendLine($"<div class=\"subtitle\">Raport Executiv Forensice &amp; Conformitate Securitate | Generat la: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</div>");
            sb.AppendLine("</div>");
            sb.AppendLine($"<div class=\"badge-mode\">{(isAirGapped ? "Ediție Standalone / Air-Gapped" : "Ediție Network SOC Enterprise")}</div>");
            sb.AppendLine("</div>");

            if (isAirGapped)
            {
                // KPI Ribbon Standalone
                sb.AppendLine("<div class=\"kpi-grid\">");
                sb.AppendLine($"<div class=\"card\"><div class=\"card-lbl\">Jurnale Securitate Stație</div><div class=\"card-val\">{adSummary.TotalAdEventsAnalyzed}</div></div>");
                sb.AppendLine($"<div class=\"card\"><div class=\"card-lbl\">Admini Locali SAM</div><div class=\"card-val\" style=\"color:#EF4444;\">{samSummary.LocalAdminGroupModifications}</div></div>");
                sb.AppendLine($"<div class=\"card\"><div class=\"card-lbl\">Medii USB Conectate</div><div class=\"card-val\" style=\"color:#F59E0B;\">{samSummary.UsbStorageEventsCount}</div></div>");
                sb.AppendLine($"<div class=\"card\"><div class=\"card-lbl\">Alterări Politici Audit</div><div class=\"card-val\" style=\"color:#F59E0B;\">{samSummary.AuditPolicyTamperingCount}</div></div>");
                sb.AppendLine($"<div class=\"card\"><div class=\"card-lbl\">Abuz SeDebugPrivilege</div><div class=\"card-val\" style=\"color:#38BDF8;\">{samSummary.HighPrivilegeAssignmentsCount}</div></div>");
                sb.AppendLine("</div>");

                // 1. Standalone SAM Findings
                sb.AppendLine("<h2>1. Detecții Securitate Stație Standalone &amp; SAM Local</h2>");
                sb.AppendLine("<table>");
                sb.AppendLine("<tr><th style=\"width:180px;\">Categorie</th><th style=\"width:220px;\">Tip Detecție</th><th style=\"width:90px;\">Severitate</th><th style=\"width:200px;\">Resursă Țintă</th><th style=\"width:90px;\">MITRE</th><th>Descriere &amp; Acțiune Recomandată</th></tr>");
                var sList = samFindings?.ToList() ?? new List<StandaloneSamFinding>();
                if (sList.Count > 0)
                {
                    foreach (var sf in sList)
                    {
                        string badgeClass = sf.Severity == "Critical" || sf.Severity == "High" ? "badge-crit" : "badge-warn";
                        sb.AppendLine($"<tr><td>{sf.Category}</td><td><strong>{sf.FindingType}</strong></td><td><span class=\"{badgeClass}\">{sf.Severity}</span></td><td>{sf.TargetAccountOrResource}</td><td>{sf.MitreTechniqueId}</td><td>{sf.Description}<br/><span style=\"color:#38BDF8;\">Măsură: {sf.RemediationActionRo}</span></td></tr>");
                    }
                }
                else
                {
                    sb.AppendLine("<tr><td colspan=\"6\" class=\"empty-row\">Nu au fost detectate anomalii locale pe baza SAM sau politici de audit.</td></tr>");
                }
                sb.AppendLine("</table>");
            }
            else
            {
                // KPI Ribbon Network
                sb.AppendLine("<div class=\"kpi-grid\">");
                sb.AppendLine($"<div class=\"card\"><div class=\"card-lbl\">Evenimente Active Directory</div><div class=\"card-val\">{adSummary.TotalAdEventsAnalyzed}</div></div>");
                sb.AppendLine($"<div class=\"card\"><div class=\"card-lbl\">Grupuri Domain Admins</div><div class=\"card-val\" style=\"color:#EF4444;\">{adSummary.PrivilegedGroupChanges}</div></div>");
                sb.AppendLine($"<div class=\"card\"><div class=\"card-lbl\">Atacuri Kerberos / AD</div><div class=\"card-val\" style=\"color:#EF4444;\">{adSummary.KerberosAttacksDetected}</div></div>");
                sb.AppendLine($"<div class=\"card\"><div class=\"card-lbl\">Modificări Politici GPO</div><div class=\"card-val\" style=\"color:#F59E0B;\">{adSummary.GpoPolicyChanges}</div></div>");
                sb.AppendLine($"<div class=\"card\"><div class=\"card-lbl\">Anomalii UBA Domeniu</div><div class=\"card-val\" style=\"color:#38BDF8;\">{ubaAnomalies?.Count() ?? 0}</div></div>");
                sb.AppendLine("</div>");

                // 1. AD Attack Findings
                sb.AppendLine("<h2>1. Detecții Atacuri Active Directory &amp; Kerberos (Domain Level)</h2>");
                sb.AppendLine("<table>");
                sb.AppendLine("<tr><th style=\"width:180px;\">Categorie</th><th style=\"width:200px;\">Tip Atac</th><th style=\"width:90px;\">Severitate</th><th style=\"width:160px;\">Cont Țintă</th><th style=\"width:90px;\">MITRE</th><th>Descriere &amp; Acțiune Recomandată</th></tr>");
                var adList = findings?.ToList() ?? new List<KerberosAdFinding>();
                if (adList.Count > 0)
                {
                    foreach (var f in adList)
                    {
                        string badgeClass = f.Severity == "Critical" || f.Severity == "High" ? "badge-crit" : "badge-warn";
                        sb.AppendLine($"<tr><td>{f.Category}</td><td><strong>{f.AttackType}</strong></td><td><span class=\"{badgeClass}\">{f.Severity}</span></td><td>{f.TargetAccount}</td><td>{f.MitreTechniqueId}</td><td>{f.Description}</td></tr>");
                    }
                }
                else
                {
                    sb.AppendLine("<tr><td colspan=\"6\" class=\"empty-row\">Nu au fost detectate atacuri Kerberos sau modificări neautorizate în Active Directory.</td></tr>");
                }
                sb.AppendLine("</table>");

                // 2. UBA Anomalies
                sb.AppendLine("<h2>2. Anomalii Comportamentale Utilizatori (User Behavior Analytics)</h2>");
                sb.AppendLine("<table>");
                sb.AppendLine("<tr><th style=\"width:160px;\">Utilizator</th><th style=\"width:220px;\">Tip Anomalie</th><th style=\"width:90px;\">Severitate</th><th style=\"width:100px;\">Punctaj Risc</th><th>Descriere Diagnostic UBA</th></tr>");
                var ubaList = ubaAnomalies?.ToList() ?? new List<UbaAnomalyItem>();
                if (ubaList.Count > 0)
                {
                    foreach (var u in ubaList)
                    {
                        string badgeClass = u.Severity == "Critical" || u.Severity == "High" ? "badge-crit" : "badge-warn";
                        sb.AppendLine($"<tr><td><strong>{u.Username}</strong></td><td>{u.AnomalyType}</td><td><span class=\"{badgeClass}\">{u.Severity}</span></td><td>{u.RiskWeight}/100</td><td>{u.Description}</td></tr>");
                    }
                }
                else
                {
                    sb.AppendLine("<tr><td colspan=\"5\" class=\"empty-row\">Nu au fost identificate anomalii comportamentale în sesiunile de domeniu.</td></tr>");
                }
                sb.AppendLine("</table>");
            }

            // 3. Compliance Matrix (Applicable to both, evaluated per environment)
            sb.AppendLine("<h2>" + (isAirGapped ? "2. Matrice Conformitate Stație Izolată (HG 585/2002, ISO/IEC 27042)" : "3. Matrice Conformitate Enterprise (Directiva NIS2, HG 585/2002, GDPR, PCI-DSS)") + "</h2>");
            sb.AppendLine("<table>");
            sb.AppendLine("<tr><th style=\"width:180px;\">Cadru Reglementar</th><th style=\"width:150px;\">Articol / Control</th><th style=\"width:200px;\">Titlu Control</th><th style=\"width:110px;\">Status</th><th>Evidență Forensică Corelată</th><th style=\"width:240px;\">Măsură Impusă</th></tr>");
            var cList = complianceResults?.ToList() ?? new List<ComplianceCheckResult>();
            if (cList.Count > 0)
            {
                foreach (var cr in cList)
                {
                    string badgeClass = cr.Status == "CONFORM" ? "badge-ok" : (cr.Status == "NON-CONFORM" ? "badge-crit" : "badge-warn");
                    sb.AppendLine($"<tr><td>{cr.Framework}</td><td>{cr.ArticleOrControl}</td><td><strong>{cr.ControlTitle}</strong></td><td><span class=\"{badgeClass}\">{cr.Status}</span></td><td>{cr.EvidenceSummary}</td><td>{cr.RequiredAction}</td></tr>");
                }
            }
            sb.AppendLine("</table>");

            sb.AppendLine("<div class=\"footer\">LogAnalyzer Enterprise — Threat Operations &amp; Incident Command Center | Conformitate HG 585/2002, Directiva NIS2, ISO/IEC 27042</div>");
            sb.AppendLine("</div>");
            sb.AppendLine("</body>");
            sb.AppendLine("</html>");

            return sb.ToString();
        }
    }
}
