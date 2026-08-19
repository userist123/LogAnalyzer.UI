using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class LateralMovementEdge
    {
        public string SourceHost { get; set; } = string.Empty;
        public string TargetHost { get; set; } = string.Empty;
        public string UserName { get; set; } = string.Empty;
        public string Protocol { get; set; } = string.Empty; // RDP, PsExec, WinRM, SMB, Named Pipe
        public DateTime Timestamp { get; set; }
        public string MitreTechniqueId { get; set; } = "T1021";
        public string EvidenceDetails { get; set; } = string.Empty;
    }

    public class LateralMovementGraph
    {
        public List<string> Nodes { get; set; } = new(); // Lista unică de mașini / IP-uri
        public List<LateralMovementEdge> Edges { get; set; } = new();
        public int TotalPivots => Edges.Count;
    }

    public class LateralMovementEngine
    {
        /// <summary>
        /// Corelează evenimentele EVTX și jurnalele de securitate pentru a construi graful orientat al mișcării laterale a atacatorului.
        /// </summary>
        public LateralMovementGraph BuildGraph(IEnumerable<ParsedEvent> events)
        {
            var graph = new LateralMovementGraph();
            if (events == null) return graph;

            var nodesSet = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var ev in events)
            {
                string host = ev.MachineName ?? "LocalHost";
                nodesSet.Add(host);

                // 1. RDP Remote Desktop (EID 4624 LogonType 10 sau TerminalServices)
                if (ev.EventId == 4624 && ev.Message != null && ev.Message.Contains("Logon Type:		10"))
                {
                    string clientIp = ExtractIp(ev.Message) ?? "Remote-Client";
                    nodesSet.Add(clientIp);

                    graph.Edges.Add(new LateralMovementEdge
                    {
                        SourceHost = clientIp,
                        TargetHost = host,
                        UserName = ExtractUser(ev.Message) ?? "Necunoscut",
                        Protocol = "RDP (Port 3389)",
                        Timestamp = ev.TimeCreated,
                        MitreTechniqueId = "T1021.001",
                        EvidenceDetails = $"Conexiune RDP interactivă de la [{clientIp}] către [{host}]."
                    });
                }
                // 2. PsExec / Servicii la Distanță (EID 7045 PSEXESVC sau EID 4697)
                else if (ev.EventId == 7045 && ev.Message != null && (ev.Message.Contains("PSEXESVC") || ev.Message.Contains("Admin$") || ev.Message.Contains("PAExec")))
                {
                    graph.Edges.Add(new LateralMovementEdge
                    {
                        SourceHost = "Rețea / Admin Share",
                        TargetHost = host,
                        UserName = "SYSTEM / Administrator",
                        Protocol = "PsExec Service Execution",
                        Timestamp = ev.TimeCreated,
                        MitreTechniqueId = "T1021.002",
                        EvidenceDetails = $"Instalare serviciu de execuție la distanță (PSEXESVC) pe [{host}]."
                    });
                }
                // 3. Network Share Authentication (EID 4624 LogonType 3 - SMB / RPC)
                else if (ev.EventId == 4624 && ev.Message != null && ev.Message.Contains("Logon Type:\t\t3") && !ev.Message.Contains("ANONYMOUS"))
                {
                    string? clientIp = ExtractIp(ev.Message);
                    if (!string.IsNullOrEmpty(clientIp) && clientIp != "127.0.0.1" && clientIp != "::1" && clientIp != "-")
                    {
                        nodesSet.Add(clientIp);
                        graph.Edges.Add(new LateralMovementEdge
                        {
                            SourceHost = clientIp,
                            TargetHost = host,
                            UserName = ExtractUser(ev.Message) ?? "SMB User",
                            Protocol = "SMB / Network Share (LogonType 3)",
                            Timestamp = ev.TimeCreated,
                            MitreTechniqueId = "T1021.002",
                            EvidenceDetails = $"Autentificare de rețea SMB de la [{clientIp}] către [{host}]."
                        });
                    }
                }
            }

            graph.Nodes = nodesSet.ToList();
            return graph;
        }

        private static string? ExtractIp(string message)
        {
            var match = System.Text.RegularExpressions.Regex.Match(message, @"(?:Source Network Address|Network Address|Source Address|Client Address):\s*([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})");
            return match.Success ? match.Groups[1].Value : null;
        }

        private static string? ExtractUser(string message)
        {
            var match = System.Text.RegularExpressions.Regex.Match(message, @"(?:Account Name|Target User Name|User Name):\s*([a-zA-Z0-9_\-\.\$]+)");
            return match.Success ? match.Groups[1].Value : null;
        }
    }
}
