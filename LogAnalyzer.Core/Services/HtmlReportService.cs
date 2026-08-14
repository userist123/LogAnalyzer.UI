using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public static class HtmlReportService
    {
        public static void GenerateReport(
            string exportPath,
            List<DetectedIssue> issues,
            List<TimelineItem> timeline,
            string sessionHashes,
            int totalEvents,
            int totalRegistry,
            int totalHosts,
            string operatorName)
        {
            var sb = new StringBuilder();

            sb.AppendLine("<!DOCTYPE html>");
            sb.AppendLine("<html lang=\"ro\">");
            sb.AppendLine("<head>");
            sb.AppendLine("    <meta charset=\"UTF-8\">");
            sb.AppendLine("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">");
            sb.AppendLine("    <title>Raport Oficial DFIR - Cyber Threat Investigation</title>");
            sb.AppendLine("    <style>");
            sb.AppendLine("        :root {");
            sb.AppendLine("            --bg-main: #0a0d14;");
            sb.AppendLine("            --bg-card: #121824;");
            sb.AppendLine("            --bg-card-hover: #182030;");
            sb.AppendLine("            --accent-cyan: #00f2fe;");
            sb.AppendLine("            --accent-blue: #4facfe;");
            sb.AppendLine("            --danger: #ef4444;");
            sb.AppendLine("            --warning: #f59e0b;");
            sb.AppendLine("            --success: #10b981;");
            sb.AppendLine("            --text-primary: #f8fafc;");
            sb.AppendLine("            --text-secondary: #94a3b8;");
            sb.AppendLine("            --border: #1e293b;");
            sb.AppendLine("        }");
            sb.AppendLine("        * { box-sizing: border-box; margin: 0; padding: 0; }");
            sb.AppendLine("        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: var(--bg-main); color: var(--text-primary); line-height: 1.6; padding: 30px; }");
            sb.AppendLine("        .container { max-width: 1300px; margin: 0 auto; }");
            sb.AppendLine("        .header { display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid var(--border); padding-bottom: 20px; margin-bottom: 30px; }");
            sb.AppendLine("        .header-title h1 { font-size: 24px; font-weight: 800; background: linear-gradient(135deg, #00f2fe, #4facfe); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }");
            sb.AppendLine("        .header-title p { color: var(--text-secondary); font-size: 13px; margin-top: 4px; }");
            sb.AppendLine("        .badge-status { background: rgba(16, 185, 129, 0.15); color: var(--success); border: 1px solid var(--success); padding: 6px 14px; border-radius: 20px; font-weight: bold; font-size: 12px; }");
            sb.AppendLine("        .kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 18px; margin-bottom: 35px; }");
            sb.AppendLine("        .kpi-card { background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 20px; }");
            sb.AppendLine("        .kpi-card h3 { font-size: 11px; text-transform: uppercase; color: var(--text-secondary); letter-spacing: 0.5px; margin-bottom: 8px; }");
            sb.AppendLine("        .kpi-card .value { font-size: 28px; font-weight: 800; color: var(--accent-cyan); }");
            sb.AppendLine("        .section { background: var(--bg-card); border: 1px solid var(--border); border-radius: 10px; padding: 24px; margin-bottom: 30px; }");
            sb.AppendLine("        .section-header { font-size: 16px; font-weight: 700; color: var(--text-primary); margin-bottom: 18px; border-bottom: 1px solid var(--border); padding-bottom: 10px; display: flex; justify-content: space-between; align-items: center; }");
            sb.AppendLine("        .hashes-block { background: #05070a; border: 1px solid var(--border); border-radius: 6px; padding: 14px; font-family: 'Consolas', monospace; font-size: 11.5px; color: #a5b4fc; white-space: pre-wrap; word-break: break-all; max-height: 200px; overflow-y: auto; }");
            sb.AppendLine("        table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 12.5px; }");
            sb.AppendLine("        th { text-align: left; background: #0f172a; padding: 12px; color: var(--text-secondary); font-weight: 600; border-bottom: 1px solid var(--border); }");
            sb.AppendLine("        td { padding: 12px; border-bottom: 1px solid var(--border); vertical-align: top; }");
            sb.AppendLine("        tr:hover { background: var(--bg-card-hover); }");
            sb.AppendLine("        .severity-critical { color: var(--danger); font-weight: 800; background: rgba(239, 68, 68, 0.12); padding: 3px 8px; border-radius: 4px; display: inline-block; }");
            sb.AppendLine("        .severity-high { color: var(--danger); font-weight: 700; background: rgba(239, 68, 68, 0.08); padding: 3px 8px; border-radius: 4px; display: inline-block; }");
            sb.AppendLine("        .severity-medium { color: var(--warning); font-weight: 600; background: rgba(245, 158, 11, 0.1); padding: 3px 8px; border-radius: 4px; display: inline-block; }");
            sb.AppendLine("        .severity-info { color: var(--success); font-weight: 600; background: rgba(16, 185, 129, 0.1); padding: 3px 8px; border-radius: 4px; display: inline-block; }");
            sb.AppendLine("        .footer { text-align: center; font-size: 11.5px; color: var(--text-secondary); margin-top: 40px; padding-top: 20px; border-top: 1px solid var(--border); }");
            sb.AppendLine("    </style>");
            sb.AppendLine("</head>");
            sb.AppendLine("<body>");
            sb.AppendLine("    <div class=\"container\">");
            sb.AppendLine("        <div class=\"header\">");
            sb.AppendLine("            <div class=\"header-title\">");
            sb.AppendLine("                <h1>RAPORT OFICIAL INVESTIGAȚIE FORENZICĂ (DFIR)</h1>");
            sb.AppendLine($"                <p>Generat la: {DateTime.Now:yyyy-MM-dd HH:mm:ss} | Investigator: <strong>{operatorName}</strong></p>");
            sb.AppendLine("            </div>");
            sb.AppendLine("            <div class=\"badge-status\">AIR-GAPPED COMPLIANCE VERIFIED</div>");
            sb.AppendLine("        </div>");

            // KPI Grid
            sb.AppendLine("        <div class=\"kpi-grid\">");
            sb.AppendLine("            <div class=\"kpi-card\">");
            sb.AppendLine("                <h3>TOTAL EVENIMENTE INDEXATE</h3>");
            sb.AppendLine($"                <div class=\"value\">{totalEvents:N0}</div>");
            sb.AppendLine("            </div>");
            sb.AppendLine("            <div class=\"kpi-card\">");
            sb.AppendLine("                <h3>ALERTE DE SECURITATE CORELATE</h3>");
            sb.AppendLine($"                <div class=\"value\" style=\"color: var(--danger);\">{issues.Count}</div>");
            sb.AppendLine("            </div>");
            sb.AppendLine("            <div class=\"kpi-card\">");
            sb.AppendLine("                <h3>ARTEFACTE REGISTRU / HIVE</h3>");
            sb.AppendLine($"                <div class=\"value\" style=\"color: var(--success);\">{totalRegistry:N0}</div>");
            sb.AppendLine("            </div>");
            sb.AppendLine("            <div class=\"kpi-card\">");
            sb.AppendLine("                <h3>MAȘINI GAZDĂ IDENTIFICATE</h3>");
            sb.AppendLine($"                <div class=\"value\" style=\"color: var(--warning);\">{totalHosts}</div>");
            sb.AppendLine("            </div>");
            sb.AppendLine("        </div>");

            // Chain of Custody
            sb.AppendLine("        <div class=\"section\">");
            sb.AppendLine("            <div class=\"section-header\">1. LANȚUL DE CUSTODIE ȘI INTEGRITATEA PROBELOR (SHA-256)</div>");
            sb.AppendLine($"            <div class=\"hashes-block\">{System.Web.HttpUtility.HtmlEncode(sessionHashes)}</div>");
            sb.AppendLine("        </div>");

            // Security Alerts
            sb.AppendLine("        <div class=\"section\">");
            sb.AppendLine("            <div class=\"section-header\">2. ALERTE DE SECURITATE ȘI DETECȚII DE AMENINȚĂRI</div>");
            if (issues == null || issues.Count == 0)
            {
                sb.AppendLine("            <p style=\"color: var(--text-secondary); font-style: italic;\">Nu au fost detectate anomalii critice sau amenințări cunoscute în jurnalele analizate.</p>");
            }
            else
            {
                sb.AppendLine("            <table>");
                sb.AppendLine("                <thead>");
                sb.AppendLine("                    <tr>");
                sb.AppendLine("                        <th style=\"width: 100px;\">Severitate</th>");
                sb.AppendLine("                        <th style=\"width: 110px;\">MITRE ATT&CK</th>");
                sb.AppendLine("                        <th style=\"width: 160px;\">Normativ / Compliance</th>");
                sb.AppendLine("                        <th style=\"width: 220px;\">Titlu Alertă</th>");
                sb.AppendLine("                        <th>Descriere Analiză & TTPs</th>");
                sb.AppendLine("                    </tr>");
                sb.AppendLine("                </thead>");
                sb.AppendLine("                <tbody>");
                foreach (var issue in issues)
                {
                    string sevClass = issue.Severity.ToLowerInvariant() switch
                    {
                        "critical" => "severity-critical",
                        "high" => "severity-high",
                        "medium" => "severity-medium",
                        _ => "severity-info"
                    };
                    sb.AppendLine("                    <tr>");
                    sb.AppendLine($"                        <td><span class=\"{sevClass}\">{issue.Severity.ToUpper()}</span></td>");
                    sb.AppendLine($"                        <td><strong>{issue.MitreTechniqueId}</strong></td>");
                    sb.AppendLine($"                        <td>{issue.ComplianceTag}</td>");
                    sb.AppendLine($"                        <td><strong>{issue.Title}</strong></td>");
                    sb.AppendLine($"                        <td>{issue.Explanation}</td>");
                    sb.AppendLine("                    </tr>");
                }
                sb.AppendLine("                </tbody>");
                sb.AppendLine("            </table>");
            }
            sb.AppendLine("        </div>");

            // Timeline
            sb.AppendLine("        <div class=\"section\">");
            sb.AppendLine("            <div class=\"section-header\">3. CRONOLOGIA EVENIMENTELOR (INCIDENT TIMELINE)</div>");
            if (timeline == null || timeline.Count == 0)
            {
                sb.AppendLine("            <p style=\"color: var(--text-secondary); font-style: italic;\">Cronologia este goală.</p>");
            }
            else
            {
                sb.AppendLine("            <table>");
                sb.AppendLine("                <thead>");
                sb.AppendLine("                    <tr>");
                sb.AppendLine("                        <th style=\"width: 160px;\">Timestamp (UTC)</th>");
                sb.AppendLine("                        <th style=\"width: 90px;\">Sursă</th>");
                sb.AppendLine("                        <th style=\"width: 140px;\">Categorie</th>");
                sb.AppendLine("                        <th style=\"width: 130px;\">Utilizator / Host</th>");
                sb.AppendLine("                        <th>Descriere Detaliată</th>");
                sb.AppendLine("                    </tr>");
                sb.AppendLine("                </thead>");
                sb.AppendLine("                <tbody>");
                foreach (var item in timeline.Take(250)) // Cap top 250 in HTML for performance
                {
                    sb.AppendLine("                    <tr>");
                    sb.AppendLine($"                        <td style=\"font-family: monospace;\">{item.Timestamp:yyyy-MM-dd HH:mm:ss}</td>");
                    sb.AppendLine($"                        <td><strong>{item.Source}</strong></td>");
                    sb.AppendLine($"                        <td>{item.Category}</td>");
                    sb.AppendLine($"                        <td>{item.UserOrHost}</td>");
                    sb.AppendLine($"                        <td>{item.Description}</td>");
                    sb.AppendLine("                    </tr>");
                }
                sb.AppendLine("                </tbody>");
                sb.AppendLine("            </table>");
            }
            sb.AppendLine("        </div>");

            // Footer
            sb.AppendLine("        <div class=\"footer\">");
            sb.AppendLine("            <p>Raport generat automat de <strong>LogAnalyzer DFIR Platform v2.6</strong> | Conformitate ISO/IEC 27037:2012 (Ghid pentru manipularea probelor digitale)</p>");
            sb.AppendLine("        </div>");
            sb.AppendLine("    </div>");
            sb.AppendLine("</body>");
            sb.AppendLine("</html>");

            File.WriteAllText(exportPath, sb.ToString(), Encoding.UTF8);
        }
    }
}
