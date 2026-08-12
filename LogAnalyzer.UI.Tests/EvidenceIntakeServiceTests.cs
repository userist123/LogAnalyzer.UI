using System;
using System.IO;
using System.Text;
using LogAnalyzer.UI.Services;
using Xunit;

namespace LogAnalyzer.UI.Tests;

public sealed class EvidenceIntakeServiceTests : IDisposable
{
    private readonly string _directory = Path.Combine(Path.GetTempPath(), "LogAnalyzerEvidence_" + Guid.NewGuid().ToString("N"));

    [Fact]
    public void Import_RecordsHashAndVerifiableCustodyEntry()
    {
        Directory.CreateDirectory(_directory);
        var evidencePath = Path.Combine(_directory, "sample.evtx");
        var custodyPath = Path.Combine(_directory, "chain.ndjson");
        File.WriteAllText(evidencePath, "evidence", Encoding.UTF8);

        var custody = new ChainOfCustodyService(custodyPath);
        var service = new EvidenceIntakeService(new SecurePathService(), custody);

        var receipt = service.Import(evidencePath, "investigator");

        Assert.Equal(Path.GetFullPath(evidencePath), receipt.FilePath);
        Assert.Equal(new FileInfo(evidencePath).Length, receipt.Length);
        Assert.Equal(new SecurePathService().ComputeSha256(evidencePath), receipt.Sha256);
        Assert.False(string.IsNullOrWhiteSpace(receipt.AuditHash));
        Assert.True(custody.Verify());
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_directory)) Directory.Delete(_directory, true); }
        catch { }
    }
}