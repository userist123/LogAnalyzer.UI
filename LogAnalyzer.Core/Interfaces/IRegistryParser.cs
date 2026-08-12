using System.Collections.Generic;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Interfaces
{
    public interface IRegistryParser
    {
        IEnumerable<RegistryArtifact> ParseRegFile(string filePath);
        IEnumerable<RegistryArtifact> ParseNtUserDat(string filePath);
    }
}