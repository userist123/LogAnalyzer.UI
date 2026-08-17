using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class ExplainableRiskFactor
    {
        public string Category { get; set; } = string.Empty; // ex: "Execuție Obfuscată", "Persistență", "Credential Access", "Anti-Forensics"
        public string Description { get; set; } = string.Empty;
        public int WeightPoints { get; set; } // puncte de impact (ex: +25)
        public string EvidenceSource { get; set; } = string.Empty; // ex: "EID 4688", "Prefetch", "Registry Run"
        public string MitreTechniqueId { get; set; } = string.Empty;
        public string LegalJustification { get; set; } = string.Empty;
    }

    public class ExplainableRiskAssessment
    {
        public int TotalScore { get; set; } // 0 - 100
        public string Level { get; set; } = "Scăzut";
        public string LevelColor { get; set; } = "#22c55e";
        public List<ExplainableRiskFactor> Factors { get; set; } = new();
        public string MathematicalFormula { get; set; } = string.Empty;
        public string ExecutiveSummaryRo { get; set; } = string.Empty;
    }

    public class ExplainableAiRiskEngine
    {
        public ExplainableRiskAssessment Evaluate(
            IEnumerable<DetectedIssue> issues, 
            int highEntropyCount, 
            int masqueradingCount, 
            int offHoursCount, 
            int yaraMatchesCount)
        {
            var assessment = new ExplainableRiskAssessment();
            var factorList = new List<ExplainableRiskFactor>();
            int rawScore = 5; // Baseline de siguranță

            // 1. Evaluare Euristică: Entropie Shannon mare
            if (highEntropyCount > 0)
            {
                int points = Math.Min(30, highEntropyCount * 10);
                rawScore += points;
                factorList.Add(new ExplainableRiskFactor
                {
                    Category = "Execuție Obfuscată (Entropie Shannon)",
                    Description = $"Identificate {highEntropyCount} comenzi/scripturi cu entropie H > 4.8 (Base64 / payload-uri comprimate).",
                    WeightPoints = points,
                    EvidenceSource = "Jurnale EVTX (EID 4688 / EID 4104)",
                    MitreTechniqueId = "T1027",
                    LegalJustification = "Prezența codului cifrat/obfuscat executat fără certificare administrativă indică intenție de eludare a controalelor EDR."
                });
            }

            // 2. Evaluare Euristică: Process Masquerading
            if (masqueradingCount > 0)
            {
                int points = Math.Min(25, masqueradingCount * 12);
                rawScore += points;
                factorList.Add(new ExplainableRiskFactor
                {
                    Category = "Camuflare Procese (Process Masquerading)",
                    Description = $"Detectate {masqueradingCount} instanțe de binare de sistem executate din directoare neautorizate (ex: %TEMP%).",
                    WeightPoints = points,
                    EvidenceSource = "Process Tree & EVTX",
                    MitreTechniqueId = "T1036.003",
                    LegalJustification = "Execuția proceselor critice de sistem din căi neobișnuite probează activitate de tip troian sau imitator de proces legitim."
                });
            }

            // 3. Evaluare Euristică: Logări Nocturne / Anomale
            if (offHoursCount > 0)
            {
                int points = Math.Min(15, offHoursCount * 5);
                rawScore += points;
                factorList.Add(new ExplainableRiskFactor
                {
                    Category = "Anomalie Temporală (Logon Off-Hours)",
                    Description = $"{offHoursCount} autentificări interactive/RDP înregistrate în afara ferestrei operaționale (01:00 - 05:00).",
                    WeightPoints = points,
                    EvidenceSource = "EVTX Security (EID 4624 / EID 4625)",
                    MitreTechniqueId = "T1078",
                    LegalJustification = "Abatere statistică semnificativă față de baseline-ul normal de activitate al utilizatorului."
                });
            }

            // 4. Semnături YARA / Malware Patterns
            if (yaraMatchesCount > 0)
            {
                int points = Math.Min(35, yaraMatchesCount * 15);
                rawScore += points;
                factorList.Add(new ExplainableRiskFactor
                {
                    Category = "Semnături Malițioase (YARA Matches)",
                    Description = $"{yaraMatchesCount} potriviri cu reguli de detectare Cobalt Strike, WebShell sau Mimikatz.",
                    WeightPoints = points,
                    EvidenceSource = "Memorie / Scripturi / Evenimente",
                    MitreTechniqueId = "T1003 / T1505.003",
                    LegalJustification = "Potrivire deterministă a tiparelor binare/regex asociate cu instrumente ofensive cunoscute."
                });
            }

            // 5. Alerte Sigma & Probleme Detectate
            if (issues != null)
            {
                foreach (var issue in issues.Take(5))
                {
                    int p = issue.Severity == "Critical" ? 15 : issue.Severity == "High" ? 10 : 5;
                    rawScore += p;
                    factorList.Add(new ExplainableRiskFactor
                    {
                        Category = "Regulă Sigma / Detecție Corelată",
                        Description = issue.Title,
                        WeightPoints = p,
                        EvidenceSource = !string.IsNullOrWhiteSpace(issue.MitreTacticName) ? issue.MitreTacticName : "EVTX Security Log",
                        MitreTechniqueId = issue.MitreTechniqueId ?? "T1059",
                        LegalJustification = issue.Explanation
                    });
                }
            }

            assessment.TotalScore = Math.Min(99, rawScore);
            assessment.Factors = factorList;
            assessment.MathematicalFormula = $"Scor Risc = Min(99, Baseline(5) + ∑ Factori Ponderați ({rawScore - 5})) = {assessment.TotalScore}/100";

            if (assessment.TotalScore >= 75)
            {
                assessment.Level = "CRITIC (Amenințare Iminentă)";
                assessment.LevelColor = "#ef4444";
                assessment.ExecutiveSummaryRo = $"Sistemul a identificat un scor cumulativ de risc critic ({assessment.TotalScore}/100) susținut de {factorList.Count} probe forenzice independente.";
            }
            else if (assessment.TotalScore >= 40)
            {
                assessment.Level = "MODERAT / RIDICAT";
                assessment.LevelColor = "#f97316";
                assessment.ExecutiveSummaryRo = $"Analiza a identificat anomalii și indicatori parțiali ({assessment.TotalScore}/100) ce justifică o investigație aprofundată.";
            }
            else
            {
                assessment.Level = "SCĂZUT (Normal / Fără incidente critice)";
                assessment.LevelColor = "#22c55e";
                assessment.ExecutiveSummaryRo = "Parametrii analizați se încadrează în limitele normale de operare a sistemului.";
            }

            return assessment;
        }
    }
}
