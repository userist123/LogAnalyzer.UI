using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Infrastructure.Parsers
{
    public class TriageCsvParser : IArtifactParser
    {
        public string ParserName => "Advanced Forensic Triage CSV Parser";
        public string SupportedFileExtension => ".csv";

        public async IAsyncEnumerable<ParsedEvent> ParseArtifactAsync(
            string filePath,
            [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            if (!File.Exists(filePath)) yield break;

            FileInfo fileInfo = new FileInfo(filePath);
            string fileName = fileInfo.Name.ToLowerInvariant();
            string machineName = ExtractMachineName(fileInfo.Name);
            DateTime fileTime = fileInfo.LastWriteTimeUtc;

            string[] lines;
            try
            {
                lines = await File.ReadAllLinesAsync(filePath, cancellationToken);
            }
            catch
            {
                yield break;
            }

            if (lines.Length <= 1) yield break;

            string header = lines[0].Trim();

            for (int i = 1; i < lines.Length; i++)
            {
                if (cancellationToken.IsCancellationRequested) yield break;

                string line = lines[i].Trim();
                if (string.IsNullOrWhiteSpace(line)) continue;

                var columns = ParseCsvLine(line);

                ParsedEvent? evt = null;

                if (fileName.Contains("dnscache"))
                {
                    evt = ParseDnsCache(columns, machineName, fileTime);
                }
                else if (fileName.Contains("kerneldrivers"))
                {
                    evt = ParseKernelDriver(columns, machineName, fileTime);
                }
                else if (fileName.Contains("scheduledtasks"))
                {
                    evt = ParseScheduledTask(columns, machineName, fileTime);
                }
                else if (fileName.Contains("localadmins") || fileName.Contains("localusers"))
                {
                    evt = ParseLocalAdmin(columns, machineName, fileTime);
                }
                else if (fileName.Contains("defenderexclusions") || fileName.Contains("defenderstatus"))
                {
                    evt = ParseDefenderExclusion(columns, machineName, fileTime);
                }
                else if (fileName.Contains("firewallrules"))
                {
                    evt = ParseFirewallRule(columns, machineName, fileTime);
                }
                else if (fileName.Contains("processes"))
                {
                    evt = ParseProcess(columns, machineName, fileTime);
                }
                else if (fileName.Contains("netstat"))
                {
                    evt = ParseNetstat(columns, machineName, fileTime);
                }

                if (evt != null)
                {
                    yield return evt;
                }
            }

            await Task.Yield();
        }

        private ParsedEvent? ParseDnsCache(List<string> cols, string machine, DateTime time)
        {
            if (cols.Count < 2) return null;
            string entry = cols[0];
            string recordName = cols.Count > 1 ? cols[1] : entry;
            string data = cols.Count > 3 ? cols[3] : string.Empty;

            bool isSuspicious = recordName.EndsWith(".ru") || recordName.EndsWith(".top") ||
                                recordName.EndsWith(".xyz") || recordName.EndsWith(".tk") ||
                                recordName.Contains("onion") || recordName.Contains("duckdns") ||
                                recordName.Contains("ngrok") || recordName.Contains("pastebin");

            return new ParsedEvent
            {
                EventId = 20101,
                TimeCreated = time,
                ProviderName = "Triage-DNSCache",
                Level = isSuspicious ? "Warning" : "Info",
                MachineName = machine,
                Message = $"[DNS Cache] Domeniu: {recordName} | Răspuns IP/Date: {data}",
                XmlData = $"<DnsEntry><Record>{recordName}</Record><Data>{data}</Data></DnsEntry>",
                OfficialDescription = isSuspicious ? "Interogare DNS către domeniu cu reputație suspectă/dinamică." : "Intrare din memoria cache a clientului DNS Windows.",
                PotentialCriticality = isSuspicious ? "Suspicious External Resolution" : "Informational"
            };
        }

        private ParsedEvent? ParseKernelDriver(List<string> cols, string machine, DateTime time)
        {
            if (cols.Count < 4) return null;
            string name = cols[0];
            string displayName = cols.Count > 1 ? cols[1] : name;
            string path = cols.Count > 3 ? cols[3] : string.Empty;
            string isSignedStr = cols.Count > 4 ? cols[4] : "False";
            string signer = cols.Count > 5 ? cols[5] : "-";

            bool isSigned = isSignedStr.Equals("True", StringComparison.OrdinalIgnoreCase);

            return new ParsedEvent
            {
                EventId = 20102,
                TimeCreated = time,
                ProviderName = "Triage-KernelDriver",
                Level = isSigned ? "Info" : "Critical",
                MachineName = machine,
                Message = $"[Kernel Driver] {name} ({displayName}) | Cale: {path} | Semnătură Validă: {(isSigned ? "DA" : "NU (NESEMNAT)")} | Semnatar: {signer}",
                XmlData = $"<Driver><Name>{name}</Name><Path>{path}</Path><IsSigned>{isSigned}</IsSigned><Signer>{signer}</Signer></Driver>",
                OfficialDescription = isSigned ? "Driver kernel Windows valid semnat digital." : "DRIVER KERNEL NESEMNAT! Posibilă tentativă de Rootkit sau exploatare BYOVD (Bring Your Own Vulnerable Driver).",
                PotentialCriticality = isSigned ? "Verified Driver" : "Critical Rootkit Risk"
            };
        }

        private ParsedEvent? ParseScheduledTask(List<string> cols, string machine, DateTime time)
        {
            if (cols.Count < 2) return null;
            string taskName = cols[0];
            string taskPath = cols.Count > 1 ? cols[1] : "\\";
            string actions = cols.Count > 3 ? cols[3] : string.Empty;
            string runAs = cols.Count > 4 ? cols[4] : string.Empty;

            bool isSuspicious = actions.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
                                actions.Contains("cmd.exe", StringComparison.OrdinalIgnoreCase) ||
                                actions.Contains("temp", StringComparison.OrdinalIgnoreCase) ||
                                actions.Contains("appdata", StringComparison.OrdinalIgnoreCase) ||
                                actions.Contains("wscript", StringComparison.OrdinalIgnoreCase) ||
                                actions.Contains("cscript", StringComparison.OrdinalIgnoreCase);

            return new ParsedEvent
            {
                EventId = 20103,
                TimeCreated = time,
                ProviderName = "Triage-ScheduledTask",
                Level = isSuspicious ? "High" : "Info",
                MachineName = machine,
                Message = $"[Scheduled Task] Nume: {taskName} | Cale: {taskPath} | Acțiune: {actions} | Rulare ca: {runAs}",
                XmlData = $"<Task><Name>{taskName}</Name><Action>{actions}</Action><RunAs>{runAs}</RunAs></Task>",
                OfficialDescription = isSuspicious ? "Sarcină programată suspectă care execută scripturi sau fișiere din directoare temporare." : "Sarcină programată de sistem Windows.",
                PotentialCriticality = isSuspicious ? "Persistence Task" : "Standard Task"
            };
        }

        private ParsedEvent? ParseLocalAdmin(List<string> cols, string machine, DateTime time)
        {
            if (cols.Count < 1) return null;
            string name = cols[0];
            string sid = cols.Count > 1 ? cols[1] : string.Empty;
            string source = cols.Count > 2 ? cols[2] : "Local";

            return new ParsedEvent
            {
                EventId = 20104,
                TimeCreated = time,
                ProviderName = "Triage-LocalAdmins",
                Level = "Warning",
                MachineName = machine,
                Message = $"[Membru Administrator Local] Cont: {name} | SID: {sid} | Sursă: {source}",
                XmlData = $"<Admin><Name>{name}</Name><SID>{sid}</SID></Admin>",
                OfficialDescription = "Cont de utilizator cu privilegii de Administrator Local pe mașina țintă.",
                PotentialCriticality = "Privilege Level Audit"
            };
        }

        private ParsedEvent? ParseDefenderExclusion(List<string> cols, string machine, DateTime time)
        {
            if (cols.Count < 2) return null;
            string pathExclusion = cols.Count > 1 ? cols[1] : string.Empty;
            string procExclusion = cols.Count > 2 ? cols[2] : string.Empty;

            if (string.IsNullOrWhiteSpace(pathExclusion) && string.IsNullOrWhiteSpace(procExclusion)) return null;

            return new ParsedEvent
            {
                EventId = 20105,
                TimeCreated = time,
                ProviderName = "Triage-DefenderExclusions",
                Level = "Critical",
                MachineName = machine,
                Message = $"[Excludere Windows Defender] Căi Excluse: {pathExclusion} | Procese Excluse: {procExclusion}",
                XmlData = $"<DefenderExclusion><Path>{pathExclusion}</Path><Process>{procExclusion}</Process></DefenderExclusion>",
                OfficialDescription = "EXCLUDERE DETECTATĂ ÎN ANTIVIRUS DEFENDER! Programele rău-intenționate folosesc excluderi pentru a rula nedetectate.",
                PotentialCriticality = "Defense Evasion (T1562.001)"
            };
        }

        private ParsedEvent? ParseFirewallRule(List<string> cols, string machine, DateTime time)
        {
            if (cols.Count < 2) return null;
            string name = cols[0];
            string displayName = cols.Count > 1 ? cols[1] : name;
            string localPort = cols.Count > 4 ? cols[4] : string.Empty;
            string program = cols.Count > 9 ? cols[9] : string.Empty;

            bool isRiskyPort = localPort.Contains("445") || localPort.Contains("3389") || localPort.Contains("5985") || localPort.Contains("135");

            return new ParsedEvent
            {
                EventId = 20106,
                TimeCreated = time,
                ProviderName = "Triage-FirewallRule",
                Level = isRiskyPort ? "Warning" : "Info",
                MachineName = machine,
                Message = $"[Regulă Firewall Inbound] {displayName} | Port Local: {localPort} | Program: {program}",
                XmlData = $"<FirewallRule><Name>{name}</Name><Port>{localPort}</Port><Program>{program}</Program></FirewallRule>",
                OfficialDescription = isRiskyPort ? "Regulă de firewall ce expune porturi administrative de rețea." : "Regulă activă în Windows Firewall.",
                PotentialCriticality = isRiskyPort ? "Network Exposure" : "Standard Rule"
            };
        }

        private ParsedEvent? ParseProcess(List<string> cols, string machine, DateTime time)
        {
            if (cols.Count < 2) return null;
            string pid = cols[0];
            string name = cols.Count > 1 ? cols[1] : string.Empty;
            string path = cols.Count > 2 ? cols[2] : string.Empty;
            string company = cols.Count > 3 ? cols[3] : string.Empty;
            string sha256 = cols.Count > 4 ? cols[4] : string.Empty;

            bool isTempPath = path.Contains("temp\\", StringComparison.OrdinalIgnoreCase) ||
                              path.Contains("appdata\\local\\temp", StringComparison.OrdinalIgnoreCase);

            return new ParsedEvent
            {
                EventId = 20107,
                TimeCreated = time,
                ProviderName = "Triage-ProcessList",
                Level = isTempPath ? "High" : "Info",
                MachineName = machine,
                Message = $"[Proces Activ] PID: {pid} | Nume: {name} | Cale: {path} | SHA256: {sha256} | Producător: {company}",
                XmlData = $"<Process><PID>{pid}</PID><Name>{name}</Name><Path>{path}</Path><SHA256>{sha256}</SHA256></Process>",
                OfficialDescription = isTempPath ? "Proces activ executat dintr-un director temporar de utilizator." : "Proces activ cules la momentul auditului.",
                PotentialCriticality = isTempPath ? "Suspicious Process Path" : "Process Baseline"
            };
        }

        private ParsedEvent? ParseNetstat(List<string> cols, string machine, DateTime time)
        {
            if (cols.Count < 4) return null;
            string localAddr = cols[0];
            string localPort = cols.Count > 1 ? cols[1] : "";
            string remoteAddr = cols.Count > 2 ? cols[2] : "";
            string remotePort = cols.Count > 3 ? cols[3] : "";
            string state = cols.Count > 4 ? cols[4] : "";
            string owningPid = cols.Count > 5 ? cols[5] : "";

            return new ParsedEvent
            {
                EventId = 20108,
                TimeCreated = time,
                ProviderName = "Triage-Netstat",
                Level = "Info",
                MachineName = machine,
                Message = $"[Conexiune Rețea] {localAddr}:{localPort} -> {remoteAddr}:{remotePort} | Stare: {state} | PID: {owningPid}",
                XmlData = $"<NetConnection><Local>{localAddr}:{localPort}</Local><Remote>{remoteAddr}:{remotePort}</Remote><State>{state}</State><PID>{owningPid}</PID></NetConnection>",
                OfficialDescription = "Conexiune TCP/UDP activă la momentul investigației.",
                PotentialCriticality = "Network Telemetry"
            };
        }

        private static string ExtractMachineName(string fileName)
        {
            var parts = fileName.Split('_');
            if (parts.Length >= 2) return parts[1];
            return "AuditHost";
        }

        private static List<string> ParseCsvLine(string line)
        {
            var result = new List<string>();
            bool inQuotes = false;
            var current = new System.Text.StringBuilder();

            for (int i = 0; i < line.Length; i++)
            {
                char c = line[i];
                if (c == '"')
                {
                    if (inQuotes && i + 1 < line.Length && line[i + 1] == '"')
                    {
                        current.Append('"');
                        i++;
                    }
                    else
                    {
                        inQuotes = !inQuotes;
                    }
                }
                else if (c == ',' && !inQuotes)
                {
                    result.Add(current.ToString().Trim());
                    current.Clear();
                }
                else
                {
                    current.Append(c);
                }
            }
            result.Add(current.ToString().Trim());
            return result;
        }
    }
}
