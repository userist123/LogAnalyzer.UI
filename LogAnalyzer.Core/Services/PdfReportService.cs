using System;
using System.Collections.Generic;
using System.IO;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using LogAnalyzer.Core.Models;

namespace LogAnalyzer.Core.Services
{
    public static class PdfReportService
    {
        public static void GenerateReport(string exportPath, List<DetectedIssue> issues, List<TimelineItem> timeline, string sessionHashes)
        {
            // QuestPDF cere configurarea licenței înainte de utilizare
            QuestPDF.Settings.License = LicenseType.Community;

            Document.Create(container =>
            {
                container.Page(page =>
                {
                    page.Size(PageSizes.A4);
                    page.Margin(40);
                    page.PageColor(Colors.White);
                    page.DefaultTextStyle(x => x.FontSize(11).FontFamily("Segoe UI"));

                    page.Header()
                        .BorderBottom(2)
                        .BorderColor(Colors.Blue.Darken2)
                        .PaddingBottom(10)
                        .Row(row =>
                        {
                            row.RelativeItem().Column(col =>
                            {
                                col.Item().Text(text =>
                                {
                                    text.Span("RAPORT FORENZIC OFICIAL (DFIR)").Bold().FontSize(18).FontColor(Colors.Blue.Darken3);
                                });
                                col.Item().Text(text =>
                                {
                                    text.Span($"Generat la: {DateTime.Now:yyyy-MM-dd HH:mm:ss}").FontSize(9).FontColor(Colors.Grey.Medium);
                                });
                            });
                        });

                    page.Content()
                        .PaddingVertical(20)
                        .Column(x =>
                        {
                            x.Spacing(15);

                            // Secțiunea 1
                            x.Item().Text(text =>
                            {
                                text.Span("1. REZUMATUL INVESTIGAȚIEI (CHAIN OF CUSTODY)").Bold().FontSize(13).FontColor(Colors.Blue.Darken2);
                            });
                            
                            x.Item().Background(Colors.Grey.Lighten4).Padding(10).Text(text =>
                            {
                                text.Span(sessionHashes).FontFamily("Consolas").FontSize(10);
                            });

                            // Secțiunea 2
                            x.Item().Text(text =>
                            {
                                text.Span("2. ALERTE DE SECURITATE CONFIRMATE").Bold().FontSize(13).FontColor(Colors.Blue.Darken2);
                            });
                            
                            if (issues == null || issues.Count == 0)
                            {
                                x.Item().Text(text =>
                                {
                                    text.Span("Nu au fost detectate alerte de securitate.").Italic();
                                });
                            }
                            else
                            {
                                foreach (var issue in issues)
                                {
                                    x.Item().BorderBottom(1).BorderColor(Colors.Grey.Lighten2).PaddingBottom(8).Column(col =>
                                    {
                                        col.Spacing(3);
                                        
                                        col.Item().Text(text =>
                                        {
                                            var severityColor = issue.Severity.Equals("Critical", StringComparison.OrdinalIgnoreCase) ? Colors.Red.Medium : Colors.Orange.Medium;
                                            text.Span($"[!] {issue.Severity.ToUpper()} - {issue.Title}").Bold().FontColor(severityColor);
                                        });
                                        
                                        col.Item().Text(text =>
                                        {
                                            text.Span(issue.Explanation);
                                        });
                                        
                                        col.Item().Text(text =>
                                        {
                                            text.Span($"MITRE ATT&CK: {issue.MitreTechniqueId} | Compliance: {issue.ComplianceTag}").Italic().FontSize(10).FontColor(Colors.Grey.Darken2);
                                        });
                                    });
                                }
                            }

                            // Secțiunea 3
                            x.Item().Text(text =>
                            {
                                text.Span("3. CRONOLOGIA EVENIMENTELOR (TIMELINE)").Bold().FontSize(13).FontColor(Colors.Blue.Darken2);
                            });
                            
                            if (timeline == null || timeline.Count == 0)
                            {
                                x.Item().Text(text =>
                                {
                                    text.Span("Nu există evenimente în timeline.").Italic();
                                });
                            }
                            else
                            {
                                foreach (var item in timeline)
                                {
                                    x.Item().PaddingVertical(2).Row(row =>
                                    {
                                        row.ConstantItem(120).Text(text =>
                                        {
                                            text.Span($"[{item.Timestamp:yyyy-MM-dd HH:mm:ss}]").FontFamily("Consolas").FontSize(9);
                                        });
                                        row.ConstantItem(60).Text(text =>
                                        {
                                            text.Span(item.Source).Bold().FontSize(9);
                                        });
                                        row.RelativeItem().Text(text =>
                                        {
                                            text.Span($"{item.Category} - {item.Description}").FontSize(9);
                                        });
                                    });
                                }
                            }
                        });

                    page.Footer()
                        .AlignCenter()
                        .Text(x =>
                        {
                            x.Span("Pagina ");
                            x.CurrentPageNumber();
                        });
                });
            })
            .GeneratePdf(exportPath);
        }
    }
}