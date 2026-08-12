using System.IO;
using DiscUtils.Registry;
using LogAnalyzer.Core.Models;
using LogAnalyzer.Core.Interfaces;
using System.Runtime.Versioning; // Adăugat pentru managementul platformei

namespace LogAnalyzer.Infrastructure.Parsers;

// Această etichetă oprește avertismentele CA1416, garantând compilatorului că rulăm pe Windows
[SupportedOSPlatform("windows")]
public class OfflineRegistryParser : IRegistryParser
{
    public IEnumerable<RegistryArtifact> ParseNtUserDat(string hivePath)
    {
        using var fs = new FileStream(hivePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var registry = new RegistryHive(fs);
        var root = registry.Root;

        var runKey = root.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Run");
        if (runKey != null)
        {
            foreach (var valName in runKey.GetValueNames())
            {
                var valData = runKey.GetValue(valName)?.ToString() ?? string.Empty;
                string suspicion = valData.Contains("AppData", StringComparison.OrdinalIgnoreCase) || 
                                   valData.Contains("Temp", StringComparison.OrdinalIgnoreCase) ? "Critical" : "Info";

                yield return new RegistryArtifact
                {
                    HiveType = "Hive Binar (.DAT)",
                    Category = "Persistence (Run Key)",
                    KeyPath = @"Software\Microsoft\Windows\CurrentVersion\Run",
                    ValueName = valName,
                    ValueData = valData,
                    SuspicionLevel = suspicion
                };
            }
        }
    }

    public IEnumerable<RegistryArtifact> ParseRegFile(string filePath)
    {
        string currentKey = string.Empty;
        
        foreach (var line in File.ReadLines(filePath))
        {
            string trimLine = line.Trim();
            
            if (string.IsNullOrWhiteSpace(trimLine) || trimLine.StartsWith(";") || trimLine.StartsWith("Windows Registry")) 
                continue;

            if (trimLine.StartsWith("[") && trimLine.EndsWith("]"))
            {
                currentKey = trimLine.Trim('[', ']');
                continue;
            }

            if (!string.IsNullOrEmpty(currentKey) && trimLine.Contains("="))
            {
                int eqIndex = trimLine.IndexOf('=');
                if (eqIndex > 0)
                {
                    string valName = trimLine.Substring(0, eqIndex).Trim('"');
                    string valData = trimLine.Substring(eqIndex + 1);

                    string suspicion = "Info";
                    if (currentKey.Contains(@"\Run", StringComparison.OrdinalIgnoreCase))
                    {
                        suspicion = "Warning";
                        if (valData.Contains("AppData", StringComparison.OrdinalIgnoreCase) || valData.Contains("Temp", StringComparison.OrdinalIgnoreCase))
                            suspicion = "Critical";
                    }

                    yield return new RegistryArtifact
                    {
                        HiveType = "Export Text (.REG)",
                        Category = currentKey.Contains(@"\Run", StringComparison.OrdinalIgnoreCase) ? "Persistență" : "Configurație",
                        KeyPath = currentKey,
                        ValueName = valName,
                        ValueData = valData.Trim('"'),
                        SuspicionLevel = suspicion
                    };
                }
            }
        }
    }
}