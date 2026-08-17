using System;
using System.Collections.Generic;
using System.Linq;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class AptActorProfile
    {
        public string ActorName { get; set; } = string.Empty; // ex: "APT29 (Cozy Bear / Nobelium)"
        public string Aliases { get; set; } = string.Empty;
        public string Origin { get; set; } = string.Empty; // ex: "Statul Rus (SVR)"
        public string TargetSectors { get; set; } = string.Empty; // ex: "Guvernamental, Apărare, Think Tanks, Energetic"
        public string KnownTools { get; set; } = string.Empty; // ex: "Cobalt Strike, Mimikatz, WellMess, EnvyScout"
        public List<string> SignatureTechniques { get; set; } = new();
        public double MatchScore { get; set; } // 0 - 100%
        public string MatchLevel { get; set; } = "Scăzut";
        public string MatchColor { get; set; } = "#38bdf8";
        public List<string> MatchedTechniques { get; set; } = new();
    }

    public class AptAttributionEngine
    {
        private readonly List<AptActorProfile> _knownActors = new()
        {
            new AptActorProfile
            {
                ActorName = "APT29 (Cozy Bear / Nobelium / Midnight Blizzard)",
                Aliases = "CozyDuke, Nobelium, Dark Halo, UNC2452",
                Origin = "Federația Rusă (SVR)",
                TargetSectors = "Guverne NATO, Ministere de Externe, Think Tanks, IT & Cloud Providers",
                KnownTools = "Cobalt Strike, EnvyScout, WellMess, GoldFinder, Mimikatz",
                SignatureTechniques = new List<string> { "T1059.001", "T1547.001", "T1562.001", "T1027", "T1053.005", "T1071.004" }
            },
            new AptActorProfile
            {
                ActorName = "APT28 (Fancy Bear / Strontium / Forest Blizzard)",
                Aliases = "Sofacy, Sednit, Pawn Storm, Tsar Team",
                Origin = "Federația Rusă (GRU)",
                TargetSectors = "Apărare, Infrastructură Critică, Aviație, Guvernamental",
                KnownTools = "X-Agent, Zebrocy, Mimikatz, Responder, CHOPSTICK",
                SignatureTechniques = new List<string> { "T1059.001", "T1003.001", "T1070.001", "T1110", "T1071.004", "T1548.002" }
            },
            new AptActorProfile
            {
                ActorName = "Lazarus Group (Hidden Cobra / Zinc)",
                Aliases = "Guardians of Peace, Diamond Sleet, AppleJeus",
                Origin = "Coreea de Nord (RGB)",
                TargetSectors = "Sector Financiar, Bănci, Criptomonede, Sectorul Aerospațial și Apărare",
                KnownTools = "Manuscrypt, BLINDINGCAN, Mimikatz, Fallchill, Brambul",
                SignatureTechniques = new List<string> { "T1059.001", "T1003.001", "T1490", "T1548.002", "T1136.001", "T1053.005" }
            },
            new AptActorProfile
            {
                ActorName = "Sandworm Team (Voodoo Bear / Seashell Blizzard)",
                Aliases = "TeleBots, BlackEnergy, Quedagh, Iridium",
                Origin = "Federația Rusă (GRU Unitatea 74455)",
                TargetSectors = "Rețele Electrice, Telecomunicații, Media, Căi Ferate",
                KnownTools = "BlackEnergy, NotPetya, Industroyer, Olympic Destroyer, CaddyWiper",
                SignatureTechniques = new List<string> { "T1070.001", "T1490", "T1059.001", "T1562.001", "T1543.003", "T1003.001" }
            },
            new AptActorProfile
            {
                ActorName = "LockBit 3.0 Ransomware Syndicate",
                Aliases = "LockBit Black, Bitwise Spider",
                Origin = "Cibercriminalitate Organizată (Ransomware-as-a-Service)",
                TargetSectors = "Sănătate, Industrie, Municipalități, Corporații Globale",
                KnownTools = "LockBit Encrypter, StealBit, Cobalt Strike, Mimikatz, vssadmin",
                SignatureTechniques = new List<string> { "T1490", "T1562.001", "T1003.001", "T1059.001", "T1070.001", "T1547.001" }
            },
            new AptActorProfile
            {
                ActorName = "Volt Typhoon (Bronze Silhouette / Vanguard Panda)",
                Aliases = "Insidious Taurus, Voltzite",
                Origin = "Republica Populară Chineză (MSS)",
                TargetSectors = "Infrastructură Critică SUA/NATO, Comunicații, Porturi, Utilități",
                KnownTools = "Living-off-the-Land Binaries (LOLBins), wmic, powershell, ntdsutil",
                SignatureTechniques = new List<string> { "T1059.001", "T1078", "T1021", "T1071.004", "T1547.001", "T1003.001" }
            }
        };

        public List<AptActorProfile> EvaluateAttribution(IEnumerable<DetectedIssue> issues)
        {
            var observedTechs = issues?
                .Where(i => !string.IsNullOrWhiteSpace(i.MitreTechniqueId))
                .Select(i => i.MitreTechniqueId!.Trim().ToUpper())
                .Distinct()
                .ToList() ?? new List<string>();

            var results = new List<AptActorProfile>();

            foreach (var actor in _knownActors)
            {
                var matched = actor.SignatureTechniques
                    .Where(st => observedTechs.Any(ot => ot.StartsWith(st) || st.StartsWith(ot)))
                    .ToList();

                double score = 0;
                if (actor.SignatureTechniques.Count > 0)
                {
                    score = (double)matched.Count / actor.SignatureTechniques.Count * 100.0;
                }

                var profileCopy = new AptActorProfile
                {
                    ActorName = actor.ActorName,
                    Aliases = actor.Aliases,
                    Origin = actor.Origin,
                    TargetSectors = actor.TargetSectors,
                    KnownTools = actor.KnownTools,
                    SignatureTechniques = actor.SignatureTechniques,
                    MatchedTechniques = matched,
                    MatchScore = Math.Round(score, 1),
                    MatchLevel = score >= 70 ? "RIDICAT (Probabilitate Mare)" : score >= 40 ? "MODERAT" : "SCĂZUT",
                    MatchColor = score >= 70 ? "#ef4444" : score >= 40 ? "#f97316" : "#38bdf8"
                };

                results.Add(profileCopy);
            }

            return results.OrderByDescending(r => r.MatchScore).ToList();
        }
    }
}
