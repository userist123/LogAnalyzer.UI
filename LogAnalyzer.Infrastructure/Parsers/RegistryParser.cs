using System.Collections.Generic;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Infrastructure
{
    public class RegistryParser : IRegistryParser
    {
        public IEnumerable<RegistryArtifact> ParseRegFile(string filePath)
        {
            // Punct de intrare pentru parserul text de regiștri
            yield break; 
        }

        public IEnumerable<RegistryArtifact> ParseNtUserDat(string filePath)
        {
            // Punct de intrare pentru extragerea Hive-urilor binare (NTUSER.DAT)
            yield break;
        }
    }
}