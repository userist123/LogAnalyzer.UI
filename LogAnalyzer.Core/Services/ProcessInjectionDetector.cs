using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class ProcessInjectionFinding
    {
        public string InjectionTechnique { get; set; } = string.Empty; // ex: "Process Hollowing", "Early Bird APC Injection", "Thread Execution Hijacking"
        public string Severity { get; set; } = "Critical";
        public string SourceProcess { get; set; } = string.Empty;
        public string TargetProcess { get; set; } = string.Empty;
        public string MitreTechniqueId { get; set; } = "T1055";
        public string Description { get; set; } = string.Empty;
        public string RecommendedContainmentRo { get; set; } = string.Empty;
        public DateTime DetectedAt { get; set; } = DateTime.UtcNow;
    }

    public class ProcessInjectionDetector
    {
        /// <summary>
        /// Detectează tehnici avansate de injectare de procese (Process Hollowing, Early Bird APC, Thread Hijacking).
        /// </summary>
        public List<ProcessInjectionFinding> DetectInjections(IEnumerable<ParsedEvent> events)
        {
            var findings = new List<ProcessInjectionFinding>();
            if (events == null) return findings;

            foreach (var ev in events)
            {
                string msg = ev.Message ?? string.Empty;
                string lowerMsg = msg.ToLowerInvariant();

                // 1. Process Hollowing: crearea unui proces în stare SUSPENDED urmată de scriere de memorie (EID 4688 / Sysmon EID 1 + 8)
                if (lowerMsg.Contains("suspended") || lowerMsg.Contains("create_suspended") || lowerMsg.Contains("process_hollowing"))
                {
                    findings.Add(new ProcessInjectionFinding
                    {
                        InjectionTechnique = "Process Hollowing (Înlocuire Imagine Executabilă în Proces Suspendat)",
                        Severity = "Critical",
                        SourceProcess = ev.MachineName ?? "Suspicious Parent",
                        TargetProcess = "Legitimate System Process (Hollowed)",
                        MitreTechniqueId = "T1055.012",
                        Description = $"Detectată instanțierea unui proces legitim în stare suspendată pentru injectarea de payload nesemnat.",
                        RecommendedContainmentRo = "1. Salvați un dump de memorie al procesului țintă.\n2. Terminați procesul părinte și cel injectat.\n3. Auditați cheile Run de persistență.",
                        DetectedAt = ev.TimeCreated
                    });
                }

                // 2. Early Bird APC Injection: Coadă APC asincronă executată înainte de Main Thread entry point
                if (lowerMsg.Contains("queueuserapc") || lowerMsg.Contains("apc_injection") || lowerMsg.Contains("earlybird"))
                {
                    findings.Add(new ProcessInjectionFinding
                    {
                        InjectionTechnique = "Early Bird APC Injection (Execuție Cod Prin Coada Asincronă APC)",
                        Severity = "Critical",
                        SourceProcess = ev.MachineName ?? "Injector Process",
                        TargetProcess = "Target Child Process",
                        MitreTechniqueId = "T1055.004",
                        Description = $"Detectată tehnica Early Bird APC: payload-ul malițios este executat prin QueueUserAPC înainte de inițializarea modulului principal al aplicației.",
                        RecommendedContainmentRo = "Blocați procesul sursă și inspectați adresele de pornire din memoria VAD a procesului.",
                        DetectedAt = ev.TimeCreated
                    });
                }

                // 3. Thread Execution Hijacking: Deschidere thread existent cu THREAD_SET_CONTEXT (Sysmon EID 8 / EID 10)
                if (lowerMsg.Contains("thread_set_context") || lowerMsg.Contains("setthreadcontext") || lowerMsg.Contains("thread_suspend_resume"))
                {
                    findings.Add(new ProcessInjectionFinding
                    {
                        InjectionTechnique = "Thread Execution Hijacking (Deturnare Pointer Instrucțiuni RIP/EIP)",
                        Severity = "Critical",
                        SourceProcess = ev.MachineName ?? "Malicious Thread Hijacker",
                        TargetProcess = "Existing Thread",
                        MitreTechniqueId = "T1055.003",
                        Description = $"Detectată manipularea contextului de execuție al unui fir existent (SetThreadContext) pentru forțarea executării de shellcode.",
                        RecommendedContainmentRo = "Izolați stația de la rețea și extrageți jurnalul de apeluri API din nucleu.",
                        DetectedAt = ev.TimeCreated
                    });
                }
            }

            return findings;
        }
    }
}
