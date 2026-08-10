using System.Collections.Generic;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Infrastructure;

public sealed class RegistryParser : IRegistryParser
{
    public IEnumerable<RegistryArtifact> ParseRegistryHive(string filePath)
    {
        return new List<RegistryArtifact>();
    }
}
