using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class LotcExfiltrationFinding
    {
        public string ToolOrChannel { get; set; } = string.Empty; // ex: "rclone.exe", "Discord Webhook", "Telegram Bot API", "mega-cmd"
        public string Severity { get; set; } = "Critical";
        public string ExfiltrationType { get; set; } = "Exfiltrare Către Servicii Cloud Legitime (LOTC)";
        public string MitreTechniqueId { get; set; } = "T1567.002";
        public string CommandLine { get; set; } = string.Empty;
        public string Description { get; set; } = string.Empty;
        public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    }

    public class LivingOffTheCloudEngine
    {
        private static readonly string[] CloudTools = new[]
        {
            "rclone", "azcopy", "mega-cmd", "megasync", "gdrive", "s3cmd", "gsutil", "transfer.sh"
        };

        private static readonly string[] WebhookKeywords = new[]
        {
            "discord.com/api/webhooks",
            "discordapp.com/api/webhooks",
            "api.telegram.org/bot",
            "pastebin.com/api",
            "transfer.sh",
            "file.io",
            "anonfiles.com",
            "catbox.moe"
        };

        /// <summary>
        /// Detectează exfiltrarea de date prin unelte de sincronizare legitime (LOTC) sau canale webhook ascunse.
        /// </summary>
        public List<LotcExfiltrationFinding> AnalyzeEvents(IEnumerable<ParsedEvent> events)
        {
            var findings = new List<LotcExfiltrationFinding>();
            if (events == null) return findings;

            foreach (var ev in events)
            {
                string msg = ev.Message ?? string.Empty;
                string lowerMsg = msg.ToLowerInvariant();

                // 1. Detecție unelte LOTC (rclone copy, azcopy copy, mega-cmd)
                foreach (var tool in CloudTools)
                {
                    if (lowerMsg.Contains(tool) && (lowerMsg.Contains("copy") || lowerMsg.Contains("sync") || lowerMsg.Contains("upload") || lowerMsg.Contains("put")))
                    {
                        findings.Add(new LotcExfiltrationFinding
                        {
                            ToolOrChannel = tool,
                            Severity = "Critical",
                            ExfiltrationType = "Exfiltrare prin Utilitare Sincronizare Cloud (LOTC)",
                            MitreTechniqueId = "T1567.002",
                            CommandLine = msg.Trim(),
                            Description = $"Detectată execuția uneltei cloud '{tool}' cu parametri de transfer de fișiere pe hostul [{ev.MachineName}]. Tehnica permite atacatorilor să exfiltreze volume mari de date fără a trezi suspiciuni.",
                            DetectedAt = ev.TimeCreated
                        });
                        break;
                    }
                }

                // 2. Detecție apeluri Webhook (Discord / Telegram / Pastebin)
                foreach (var hook in WebhookKeywords)
                {
                    if (lowerMsg.Contains(hook))
                    {
                        findings.Add(new LotcExfiltrationFinding
                        {
                            ToolOrChannel = hook,
                            Severity = "Critical",
                            ExfiltrationType = "Exfiltrare / C2 prin Webhook API",
                            MitreTechniqueId = "T1567.001",
                            CommandLine = msg.Trim(),
                            Description = $"Detectată interogare către canalul webhook/API '{hook}'. Atacatorii folosesc boți de mesagerie pentru a descărca credențiale sau a recepționa date furate.",
                            DetectedAt = ev.TimeCreated
                        });
                        break;
                    }
                }
            }

            return findings;
        }
    }
}
