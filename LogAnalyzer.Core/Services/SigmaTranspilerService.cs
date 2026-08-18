using System;
using System.Text;
using System.Text.RegularExpressions;

namespace LogAnalyzer.Core.Services
{
    public class TranspiledRuleResult
    {
        public string RuleTitle { get; set; } = string.Empty;
        public string SplunkSpl { get; set; } = string.Empty;
        public string SentinelKql { get; set; } = string.Empty;
        public string PowerShellHunting { get; set; } = string.Empty;
    }

    public class SigmaTranspilerService
    {
        /// <summary>
        /// Transpilează o regulă Sigma în formate de interogare utilizate în SIEM-uri enterprise (Splunk SPL, Microsoft Sentinel KQL, PowerShell).
        /// </summary>
        public TranspiledRuleResult Transpile(string ruleTitle, string eventId, string imageCondition, string commandLineContains)
        {
            var result = new TranspiledRuleResult
            {
                RuleTitle = ruleTitle
            };

            // 1. Splunk SPL
            var spl = new StringBuilder();
            spl.Append("index=security ");
            if (!string.IsNullOrWhiteSpace(eventId))
            {
                spl.Append($"(EventCode={eventId} OR EventID={eventId}) ");
            }
            if (!string.IsNullOrWhiteSpace(imageCondition))
            {
                spl.Append($"Image=\"*{Escape(imageCondition)}*\" ");
            }
            if (!string.IsNullOrWhiteSpace(commandLineContains))
            {
                spl.Append($"CommandLine=\"*{Escape(commandLineContains)}*\" ");
            }
            spl.Append("| table _time, host, User, Image, CommandLine, ParentImage");
            result.SplunkSpl = spl.ToString();

            // 2. Microsoft Sentinel KQL
            var kql = new StringBuilder();
            kql.AppendLine("SecurityEvent");
            if (!string.IsNullOrWhiteSpace(eventId))
            {
                kql.AppendLine($"| where EventID == {eventId}");
            }
            if (!string.IsNullOrWhiteSpace(imageCondition))
            {
                kql.AppendLine($"| where Process has \"{Escape(imageCondition)}\" or NewProcessName has \"{Escape(imageCondition)}\"");
            }
            if (!string.IsNullOrWhiteSpace(commandLineContains))
            {
                kql.AppendLine($"| where CommandLine has \"{Escape(commandLineContains)}\"");
            }
            kql.Append("| project TimeGenerated, Computer, Account, Process, CommandLine, ParentProcessName");
            result.SentinelKql = kql.ToString();

            // 3. PowerShell Local Hunting Script (Air-Gapped)
            var ps = new StringBuilder();
            ps.AppendLine("# PowerShell Air-Gapped Hunting Script");
            ps.AppendLine($"# Regula: {ruleTitle}");
            ps.AppendLine("Get-WinEvent -FilterHashtable @{");
            ps.AppendLine("    LogName = 'Security'");
            if (!string.IsNullOrWhiteSpace(eventId))
            {
                ps.AppendLine($"    Id = {eventId}");
            }
            ps.AppendLine("} -MaxEvents 500 -ErrorAction SilentlyContinue | Where-Object {");
            
            var conditions = new StringBuilder();
            if (!string.IsNullOrWhiteSpace(commandLineContains))
            {
                conditions.Append($"$_.Message -match '{EscapeRegex(commandLineContains)}'");
            }
            if (!string.IsNullOrWhiteSpace(imageCondition))
            {
                if (conditions.Length > 0) conditions.Append(" -and ");
                conditions.Append($"$_.Message -match '{EscapeRegex(imageCondition)}'");
            }
            if (conditions.Length == 0) conditions.Append("$true");
            
            ps.AppendLine($"    {conditions}");
            ps.AppendLine("} | Select-Object TimeCreated, Id, MachineName, Message");
            result.PowerShellHunting = ps.ToString();

            return result;
        }

        private static string Escape(string input)
        {
            if (string.IsNullOrEmpty(input)) return string.Empty;
            return input.Replace("\"", "\\\"");
        }

        private static string EscapeRegex(string input)
        {
            if (string.IsNullOrEmpty(input)) return string.Empty;
            return Regex.Escape(input);
        }
    }
}
