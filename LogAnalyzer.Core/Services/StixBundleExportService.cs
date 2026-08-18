using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public class StixBundleExportService
    {
        /// <summary>
        /// Generează un pachet complet OASIS STIX 2.1 JSON compatibil cu platformele OpenCTI, MISP și SOAR.
        /// </summary>
        public string ExportToStix21Json(string incidentId, string threatActorName, IEnumerable<IocItem> iocs, IEnumerable<DetectedIssue> issues)
        {
            string bundleId = $"bundle--{Guid.NewGuid()}";
            string identityId = $"identity--{Guid.NewGuid()}";
            string threatActorId = $"threat-actor--{Guid.NewGuid()}";
            string nowIso = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");

            var objects = new List<object>();

            // 1. Identity (Organizație / SOC)
            objects.Add(new Dictionary<string, object>
            {
                { "type", "identity" },
                { "spec_version", "2.1" },
                { "id", identityId },
                { "created", nowIso },
                { "modified", nowIso },
                { "name", "LogAnalyzer DFIR SOC Team" },
                { "identity_class", "organization" }
            });

            // 2. Threat Actor
            if (!string.IsNullOrWhiteSpace(threatActorName))
            {
                objects.Add(new Dictionary<string, object>
                {
                    { "type", "threat-actor" },
                    { "spec_version", "2.1" },
                    { "id", threatActorId },
                    { "created", nowIso },
                    { "modified", nowIso },
                    { "name", threatActorName },
                    { "threat_actor_types", new[] { "apt", "cybercrime" } }
                });
            }

            // 3. Indicators (IOCs)
            if (iocs != null)
            {
                foreach (var ioc in iocs)
                {
                    string indId = $"indicator--{Guid.NewGuid()}";
                    string pattern = ioc.Type == IocType.Hash
                        ? $"[file:hashes.'SHA-256' = '{ioc.Value}']"
                        : (ioc.Type == IocType.IPv4
                            ? $"[ipv4-addr:value = '{ioc.Value}']"
                            : $"[domain-name:value = '{ioc.Value}']");

                    objects.Add(new Dictionary<string, object>
                    {
                        { "type", "indicator" },
                        { "spec_version", "2.1" },
                        { "id", indId },
                        { "created", nowIso },
                        { "modified", nowIso },
                        { "name", $"IOC {ioc.Type}: {ioc.Value}" },
                        { "pattern", pattern },
                        { "pattern_type", "stix" },
                        { "valid_from", nowIso }
                    });
                }
            }

            // 4. Attack Patterns from Issues
            if (issues != null)
            {
                foreach (var issue in issues.Take(10))
                {
                    string apId = $"attack-pattern--{Guid.NewGuid()}";
                    objects.Add(new Dictionary<string, object>
                    {
                        { "type", "attack-pattern" },
                        { "spec_version", "2.1" },
                        { "id", apId },
                        { "created", nowIso },
                        { "modified", nowIso },
                        { "name", string.IsNullOrWhiteSpace(issue.Title) ? "Detecție Securitate" : issue.Title },
                        { "description", issue.Explanation ?? string.Empty },
                        { "external_references", new[] {
                            new Dictionary<string, string>
                            {
                                { "source_name", "mitre-attack" },
                                { "external_id", issue.MitreTechniqueId ?? "T1059" }
                            }
                        }}
                    });
                }
            }

            var bundle = new Dictionary<string, object>
            {
                { "type", "bundle" },
                { "id", bundleId },
                { "objects", objects }
            };

            return JsonSerializer.Serialize(bundle, new JsonSerializerOptions { WriteIndented = true });
        }
    }
}
