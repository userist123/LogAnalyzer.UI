using System.Collections.Generic;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Interfaces
{
    public interface IEventParser
    {
        IEnumerable<ParsedEvent> ParseEvtxFile(string filePath);
    }
}