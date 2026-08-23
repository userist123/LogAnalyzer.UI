using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class ProcessLineageCorrelator
    {
        public List<CorrelatedProcessNode> BuildLineageTrees(IEnumerable<ParsedEvent> events)
        {
            var roots = new List<CorrelatedProcessNode>();
            if (events == null) return roots;

            var list = events.ToList();

            // Sysmon EID 1 (Process Create) sau Windows Security EID 4688 (Process Creation)
            var procEvents = list.Where(e => e.EventId == 1 || e.EventId == 4688).ToList();
            if (procEvents.Count == 0) return roots;

            var nodes = new List<CorrelatedProcessNode>();

            foreach (var e in procEvents)
            {
                string msg = e.Message ?? string.Empty;
                string img = ExtractField(msg, "Image:") ?? ExtractField(msg, "New Process Name:") ?? "unknown.exe";
                string procName = System.IO.Path.GetFileName(img);
                string cmd = ExtractField(msg, "CommandLine:") ?? ExtractField(msg, "Process Command Line:") ?? img;
                string pid = ExtractField(msg, "ProcessId:") ?? ExtractField(msg, "New Process ID:") ?? "0x0";
                string ppid = ExtractField(msg, "ParentProcessId:") ?? ExtractField(msg, "Creator Process ID:") ?? "0x0";
                string pimg = ExtractField(msg, "ParentImage:") ?? ExtractField(msg, "Parent Process Name:") ?? "explorer.exe";
                string pName = System.IO.Path.GetFileName(pimg);
                string user = ExtractField(msg, "User:") ?? ExtractField(msg, "SubjectUserName:") ?? "SYSTEM";

                bool isSuspicious = false;
                string reason = string.Empty;

                if (cmd.Contains("-enc", StringComparison.OrdinalIgnoreCase) || cmd.Contains("bypass", StringComparison.OrdinalIgnoreCase) || cmd.Contains("downloadstring", StringComparison.OrdinalIgnoreCase))
                {
                    isSuspicious = true;
                    reason = "PowerShell Script Codificat / Obfuscat";
                }
                else if (pName.Equals("winword.exe", StringComparison.OrdinalIgnoreCase) || pName.Equals("excel.exe", StringComparison.OrdinalIgnoreCase))
                {
                    if (procName.Equals("cmd.exe", StringComparison.OrdinalIgnoreCase) || procName.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase) || procName.Equals("wscript.exe", StringComparison.OrdinalIgnoreCase))
                    {
                        isSuspicious = true;
                        reason = "Execuție Proces Copil Malicios din Microsoft Office (Macro Payload)";
                    }
                }
                else if (img.Contains(@"\AppData\Local\Temp\", StringComparison.OrdinalIgnoreCase))
                {
                    isSuspicious = true;
                    reason = "Execuție din Directoriu Temporar (%TEMP% Masquerading)";
                }

                nodes.Add(new CorrelatedProcessNode
                {
                    ProcessId = pid,
                    ProcessName = procName,
                    ImagePath = img,
                    CommandLine = cmd,
                    ParentProcessId = ppid,
                    ParentProcessName = pName,
                    User = user,
                    ExecutionTime = e.TimeCreated,
                    IsSuspicious = isSuspicious,
                    AnomalyReason = reason
                });
            }

            // Corelare părinte-copil
            var nodeDict = nodes.ToLookup(n => n.ParentProcessId);
            foreach (var node in nodes)
            {
                node.Children = nodeDict[node.ProcessId].ToList();
            }

            // Rădăcini: noduri al căror părinte nu se află în lista curentă
            var allPids = new HashSet<string>(nodes.Select(n => n.ProcessId));
            roots = nodes.Where(n => !allPids.Contains(n.ParentProcessId) || n.ParentProcessId == "0x0" || n.ParentProcessId == "0").ToList();

            return roots;
        }

        private static string? ExtractField(string text, string fieldLabel)
        {
            if (string.IsNullOrEmpty(text)) return null;
            int idx = text.IndexOf(fieldLabel, StringComparison.OrdinalIgnoreCase);
            if (idx < 0) return null;

            int start = idx + fieldLabel.Length;
            int end = text.IndexOf('\n', start);
            if (end < 0) end = text.Length;

            var val = text.Substring(start, end - start).Trim();
            return string.IsNullOrEmpty(val) ? null : val;
        }
    }
}
