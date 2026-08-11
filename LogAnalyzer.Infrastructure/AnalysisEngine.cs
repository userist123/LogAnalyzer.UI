using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Infrastructure;

public sealed class AnalysisEngine : IAnalysisEngine
{
    private static readonly string[] SuspiciousCommandLinePatterns =
    {
        "-enc", "-encodedcommand", "-nop", "-noprofile", "-w hidden", "-windowstyle hidden",
        "bypass", "mimikatz", "invoke-expression", "iex(", "downloadstring", "certutil -urlcache",
        "certutil -decode", "bitsadmin /transfer", "whoami /priv", "vssadmin delete shadows",
        "reg save", "comsvcs.dll", "rundll32", "regsvr32 /s /u /i:"
    };

    public IEnumerable<DetectedIssue> AnalyzeEvents(List<ParsedEvent> events)
    {
        var issues = new List<DetectedIssue>();

        AddBruteForce(events, issues);
        AddLogClearing(events, issues);
        AddSuspiciousLogon(events, issues);
        AddSpecialPrivileges(events, issues);
        AddNewAccount(events, issues);
        AddGroupMembershipChange(events, issues);
        AddSuspiciousProcess(events, issues);
        AddScheduledTask(events, issues);
        AddAuditPolicyChange(events, issues);
        AddKerberosAnomalies(events, issues);
        AddShareAccess(events, issues);
        AddNewService(events, issues);
        AddSysmonSuspiciousParentChild(events, issues);

        return issues;
    }

    private static void AddBruteForce(List<ParsedEvent> events, List<DetectedIssue> issues)
    {
        var bruteForce = events.Where(e => e.EventId == 4625).ToList();
        if (bruteForce.Count >= 5)
        {
            issues.Add(new DetectedIssue
            {
                Title = $"Posibil atac de forță brută ({bruteForce.Count} autentificări eșuate)",
                Severity = "High",
                Explanation = "Detectate multiple evenimente EID 4625 (autentificare eșuată) pe aceeași stație.",
                MitreTechniqueId = "T1110",
                ComplianceTag = "HG585 Art. 282"
            });
        }
    }

    private static void AddLogClearing(List<ParsedEvent> events, List<DetectedIssue> issues)
    {
        var logClearing = events.Where(e => e.EventId == 1102 || e.EventId == 104).ToList();
        foreach (var evt in logClearing)
        {
            issues.Add(new DetectedIssue
            {
                Title = "Ștergere jurnal de evenimente detectată",
                Severity = "Critical",
                Explanation = $"Evenimentul EID {evt.EventId} indică o posibilă tentativă de evaziune prin ștergerea jurnalelor.",
                MitreTechniqueId = "T1070.001",
                ComplianceTag = "HG585 Art. 312"
            });
        }
    }

    private static void AddSuspiciousLogon(List<ParsedEvent> events, List<DetectedIssue> issues)
    {
        var remoteLogons = events.Where(e => e.EventId == 4624 && (e.LogonType == "10" || e.LogonType == "3")).ToList();
        foreach (var evt in remoteLogons)
        {
            issues.Add(new DetectedIssue
            {
                Title = $"Autentificare la distanță: {evt.TargetUserName} (tip {evt.LogonType}) din {(string.IsNullOrWhiteSpace(evt.IpAddress) ? "IP necunoscut" : evt.IpAddress)}",
                Severity = evt.LogonType == "10" ? "Medium" : "Low",
                Explanation = $"Logon reușit EID 4624, tip {evt.LogonType} (10=RDP, 3=rețea), stație sursă {evt.WorkstationName}.",
                MitreTechniqueId = "T1078",
                ComplianceTag = "HG585 Art. 282"
            });
        }
    }

    private static void AddSpecialPrivileges(List<ParsedEvent> events, List<DetectedIssue> issues)
    {
        foreach (var evt in events.Where(e => e.EventId == 4672))
        {
            issues.Add(new DetectedIssue
            {
                Title = $"Privilegii speciale asignate contului {evt.TargetUserName}",
                Severity = "Medium",
                Explanation = "EID 4672 indică acordarea de privilegii de tip administrator/SYSTEM la logon.",
                MitreTechniqueId = "T1078.003",
                ComplianceTag = "HG585 Art. 282"
            });
        }
    }

    private static void AddNewAccount(List<ParsedEvent> events, List<DetectedIssue> issues)
    {
        foreach (var evt in events.Where(e => e.EventId == 4720))
        {
            issues.Add(new DetectedIssue
            {
                Title = $"Cont nou creat: {evt.TargetUserName}",
                Severity = "Medium",
                Explanation = "EID 4720 - creare cont de utilizator, verifică dacă este autorizată.",
                MitreTechniqueId = "T1136.001",
                ComplianceTag = "HG585 Art. 282"
            });
        }
    }

    private static void AddGroupMembershipChange(List<ParsedEvent> events, List<DetectedIssue> issues)
    {
        foreach (var evt in events.Where(e => e.EventId == 4732 || e.EventId == 4728))
        {
            issues.Add(new DetectedIssue
            {
                Title = $"Membru adăugat într-un grup securizat: {evt.TargetUserName}",
                Severity = "High",
                Explanation = $"EID {evt.EventId} - posibilă escaladare de privilegii prin adăugarea unui cont într-un grup cu drepturi ridicate.",
                MitreTechniqueId = "T1098",
                ComplianceTag = "HG585 Art. 282"
            });
        }
    }

    private static void AddSuspiciousProcess(List<ParsedEvent> events, List<DetectedIssue> issues)
    {
        var processEvents = events.Where(e => e.EventId == 4688 || e.EventId == 1);
        foreach (var evt in processEvents)
        {
            var haystack = (evt.CommandLine + " " + evt.ProcessName).ToLowerInvariant();
            if (SuspiciousCommandLinePatterns.Any(p => haystack.Contains(p)))
            {
                issues.Add(new DetectedIssue
                {
                    Title = $"Linie de comandă suspectă: {evt.ProcessName}",
                    Severity = "High",
                    Explanation = $"Procesul {evt.ProcessName} a fost lansat cu parametri suspecți: {evt.CommandLine}",
                    MitreTechniqueId = "T1059",
                    ComplianceTag = "HG585 Art. 282"
                });
            }
        }
    }

    private static void AddScheduledTask(List<ParsedEvent> events, List<DetectedIssue> issues)
    {
        foreach (var evt in events.Where(e => e.EventId == 4698))
        {
            issues.Add(new DetectedIssue
            {
                Title = "Task programat nou creat",
                Severity = "Medium",
                Explanation = "EID 4698 - crearea unui task programat poate indica mecanism de persistență.",
                MitreTechniqueId = "T1053.005",
                ComplianceTag = "HG585 Art. 282"
            });
        }
    }

    private static void AddAuditPolicyChange(List<ParsedEvent> events, List<DetectedIssue> issues)
    {
        foreach (var evt in events.Where(e => e.EventId == 4719))
        {
            issues.Add(new DetectedIssue
            {
                Title = "Politica de audit a fost modificată",
                Severity = "High",
                Explanation = "EID 4719 - modificarea politicii de audit poate fi folosită pentru a ascunde activitatea următoare.",
                MitreTechniqueId = "T1562.002",
                ComplianceTag = "HG585 Art. 312"
            });
        }
    }

    private static void AddKerberosAnomalies(List<ParsedEvent> events, List<DetectedIssue> issues)
    {
        var kerberosFailures = events.Where(e => e.EventId == 4771).ToList();
        if (kerberosFailures.Count >= 3)
        {
            issues.Add(new DetectedIssue
            {
                Title = $"Autentificări Kerberos eșuate repetate ({kerberosFailures.Count})",
                Severity = "High",
                Explanation = "EID 4771 repetat poate indica un atac de tip password spraying sau brute force Kerberos.",
                MitreTechniqueId = "T1110",
                ComplianceTag = "HG585 Art. 282"
            });
        }

        var ticketRequests = events.Where(e => e.EventId == 4769).ToList();
        var groupedByUser = ticketRequests.GroupBy(e => e.SubjectUserName).Where(g => g.Count() >= 10);
        foreach (var group in groupedByUser)
        {
            issues.Add(new DetectedIssue
            {
                Title = $"Posibil Kerberoasting - {group.Key} a solicitat {group.Count()} tichete de serviciu",
                Severity = "High",
                Explanation = "EID 4769 repetat pentru același cont poate indica extragerea de tichete de serviciu pentru crack offline.",
                MitreTechniqueId = "T1558.003",
                ComplianceTag = "HG585 Art. 282"
            });
        }
    }

    private static void AddShareAccess(List<ParsedEvent> events, List<DetectedIssue> issues)
    {
        var adminShareAccess = events.Where(e => e.EventId == 5140 &&
            (e.Message.Contains("ADMIN$", StringComparison.OrdinalIgnoreCase) || e.Message.Contains("C$", StringComparison.OrdinalIgnoreCase))).ToList();
        foreach (var evt in adminShareAccess)
        {
            issues.Add(new DetectedIssue
            {
                Title = $"Acces la share administrativ: {evt.SubjectUserName}",
                Severity = "Medium",
                Explanation = "EID 5140 - acces la un share administrativ (ADMIN$/C$) poate indica mișcare laterală.",
                MitreTechniqueId = "T1021.002",
                ComplianceTag = "HG585 Art. 282"
            });
        }
    }

    private static void AddNewService(List<ParsedEvent> events, List<DetectedIssue> issues)
    {
        foreach (var evt in events.Where(e => e.EventId == 7045 || e.EventId == 4697))
        {
            issues.Add(new DetectedIssue
            {
                Title = $"Serviciu nou instalat: {evt.ProcessName}",
                Severity = "High",
                Explanation = $"EID {evt.EventId} - instalarea unui serviciu nou este o tehnică comună de persistență.",
                MitreTechniqueId = "T1543.003",
                ComplianceTag = "HG585 Art. 282"
            });
        }
    }

    private static void AddSysmonSuspiciousParentChild(List<ParsedEvent> events, List<DetectedIssue> issues)
    {
        var suspiciousPairs = new (string Parent, string Child)[]
        {
            ("winword.exe", "cmd.exe"), ("winword.exe", "powershell.exe"),
            ("excel.exe", "cmd.exe"), ("excel.exe", "powershell.exe"),
            ("outlook.exe", "powershell.exe"), ("outlook.exe", "cmd.exe")
        };

        foreach (var evt in events.Where(e => e.EventId == 1 && !string.IsNullOrWhiteSpace(e.ParentProcessName) && !string.IsNullOrWhiteSpace(e.ProcessName)))
        {
            var parent = System.IO.Path.GetFileName(evt.ParentProcessName).ToLowerInvariant();
            var child = System.IO.Path.GetFileName(evt.ProcessName).ToLowerInvariant();

            if (suspiciousPairs.Any(p => parent.Contains(p.Parent) && child.Contains(p.Child)))
            {
                issues.Add(new DetectedIssue
                {
                    Title = $"Lanț proces suspect: {parent} a lansat {child}",
                    Severity = "Critical",
                    Explanation = "O aplicație de tip document Office a lansat un interpretor de comenzi, tipic pentru malware livrat prin macro.",
                    MitreTechniqueId = "T1204.002",
                    ComplianceTag = "HG585 Art. 282"
                });
            }
        }
    }
}
