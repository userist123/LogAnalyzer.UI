using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services;

public static class PdfReportService
{
    public static void GenerateReport(string filePath, List<DetectedIssue> issues, List<TimelineItem> timeline, string hashesLabel)
    {
        var builder = new StringBuilder();
        builder.AppendLine("LogAnalyzer.MVP - Raport Forenzic");
        builder.AppendLine($"Generat: {System.DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        builder.AppendLine();
        builder.AppendLine("== Alerte ==");
        foreach (var issue in issues)
            builder.AppendLine($"[{issue.Severity}] {issue.Title} - {issue.Explanation}");
        builder.AppendLine();
        builder.AppendLine("== Cronologie ==");
        foreach (var item in timeline.OrderBy(t => t.Timestamp))
            builder.AppendLine($"{item.Timestamp:yyyy-MM-dd HH:mm:ss} [{item.Source}] {item.Description}");
        builder.AppendLine();
        builder.AppendLine(hashesLabel);
        File.WriteAllText(filePath, builder.ToString(), new UTF8Encoding(false));
    }
}
