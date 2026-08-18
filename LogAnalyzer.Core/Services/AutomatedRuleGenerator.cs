using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class GeneratedRulesPackage
    {
        public string YARA_Rule { get; set; } = string.Empty;
        public string Sigma_YAML_Rule { get; set; } = string.Empty;
        public int TotalIocsIncluded { get; set; }
    }

    public class AutomatedRuleGenerator
    {
        /// <summary>
        /// Generează automat o regulă YARA și o regulă Sigma YAML pornind de la o listă de IOC-uri colectate din investigație.
        /// </summary>
        public GeneratedRulesPackage GenerateRulesFromIocs(string incidentId, IEnumerable<IocItem> iocs)
        {
            var result = new GeneratedRulesPackage();
            if (iocs == null) return result;

            var iocList = iocs.ToList();
            result.TotalIocsIncluded = iocList.Count;

            string safeId = string.IsNullOrWhiteSpace(incidentId) ? "INCIDENT_" + DateTime.UtcNow.ToString("yyyyMMdd_HHmm") : incidentId.Replace("-", "_").Replace(" ", "_");

            // 1. Generare Regulă YARA
            var yara = new StringBuilder();
            yara.AppendLine($"rule Incident_{safeId}_ThreatDetection");
            yara.AppendLine("{");
            yara.AppendLine("    meta:");
            yara.AppendLine($"        description = \"Regulă YARA generată automat din artefactele incidentului {safeId}\"");
            yara.AppendLine($"        author = \"LogAnalyzer Enterprise AI\"");
            yara.AppendLine($"        date = \"{DateTime.UtcNow:yyyy-MM-dd}\"");
            yara.AppendLine("        reference = \"ISO/IEC 27042 Forensic Extraction\"");
            yara.AppendLine("    strings:");

            int strIndex = 1;

            foreach (var ioc in iocList)
            {
                if (ioc.Type == IocType.Hash)
                {
                    string cleanVal = ioc.Value.Replace("\\", "\\\\").Replace("\"", "\\\"");
                    yara.AppendLine($"        $hash{strIndex++} = \"{cleanVal}\" ascii wide nocase");
                }
                else
                {
                    string cleanVal = ioc.Value.Replace("\\", "\\\\").Replace("\"", "\\\"");
                    yara.AppendLine($"        $s{strIndex++} = \"{cleanVal}\" ascii wide nocase");
                }
            }

            if (strIndex == 1)
            {
                yara.AppendLine("        $s1 = \"mimikatz\" ascii wide nocase");
                yara.AppendLine("        $s2 = \"sekurlsa\" ascii wide nocase");
            }

            yara.AppendLine("    condition:");
            yara.AppendLine("        any of them");
            yara.AppendLine("}");
            result.YARA_Rule = yara.ToString();

            // 2. Generare Regulă Sigma YAML
            var sigma = new StringBuilder();
            sigma.AppendLine($"title: Detecție IOC Incident {safeId}");
            sigma.AppendLine($"id: {Guid.NewGuid()}");
            sigma.AppendLine("status: experimental");
            sigma.AppendLine($"description: Regulă Sigma generată automat din {iocList.Count} indicatori de compromitere (IOC).");
            sigma.AppendLine("author: LogAnalyzer DFIR Engine");
            sigma.AppendLine($"date: {DateTime.UtcNow:yyyy-MM-dd}");
            sigma.AppendLine("logsource:");
            sigma.AppendLine("    category: process_creation");
            sigma.AppendLine("    product: windows");
            sigma.AppendLine("detection:");
            sigma.AppendLine("    selection:");
            sigma.AppendLine("        CommandLine|contains:");

            if (iocList.Count > 0)
            {
                foreach (var ioc in iocList.Take(15))
                {
                    sigma.AppendLine($"            - '{ioc.Value.Replace("'", "''")}'");
                }
            }
            else
            {
                sigma.AppendLine("            - 'powershell -enc'");
                sigma.AppendLine("            - 'vssadmin delete'");
            }

            sigma.AppendLine("    condition: selection");
            sigma.AppendLine("falsepositives:");
            sigma.AppendLine("    - Activitate legitimă de administrare a sistemului");
            sigma.AppendLine("level: critical");
            sigma.AppendLine("tags:");
            sigma.AppendLine("    - attack.execution");
            sigma.AppendLine("    - attack.t1059");

            result.Sigma_YAML_Rule = sigma.ToString();
            return result;
        }
    }
}
