using System;
using System.IO;
using System.Text;
using LogAnalyzer.UI.Services;
using Xunit;

namespace LogAnalyzer.UI.Tests;

public sealed class ChainOfCustodyServiceTests : IDisposable
{
    private readonly string _dir = Path.Combine(Path.GetTempPath(), "LogAnalyzerTests_" + Guid.NewGuid().ToString("N"));
    private string LogPath => Path.Combine(_dir, "custody.log");

    [Fact]
    public void Append_ThenVerify_IsValid()
    {
        Directory.CreateDirectory(_dir);
        var service = new ChainOfCustodyService(LogPath);
        service.Append("analyst1", "CASE_OPENED", "Case=IR-2026-001");
        service.Append("analyst1", "EVIDENCE_IMPORTED", "Path=security.evtx;SHA256=abc");
        Assert.True(service.Verify());
    }

    [Fact]
    public void TamperedEntry_FailsVerification()
    {
        Directory.CreateDirectory(_dir);
        var service = new ChainOfCustodyService(LogPath);
        service.Append("analyst1", "CASE_OPENED", "Case=IR-2026-001");
        service.Append("analyst1", "EVIDENCE_IMPORTED", "Path=security.evtx");

        var text = File.ReadAllText(LogPath, Encoding.UTF8);
        var tampered = text.Replace("EVIDENCE_IMPORTED", "EVIDENCE_DELETED");
        File.WriteAllText(LogPath, tampered, Encoding.UTF8);

        var verifier = new ChainOfCustodyService(LogPath);
        Assert.False(verifier.Verify());
    }

    [Fact]
    public void ResumeAfterRestart_ContinuesChain()
    {
        Directory.CreateDirectory(_dir);
        var first = new ChainOfCustodyService(LogPath);
        var e1 = first.Append("analyst1", "ACTION1", "details");

        var second = new ChainOfCustodyService(LogPath);
        var e2 = second.Append("analyst1", "ACTION2", "details2");

        Assert.Equal(e1.Hash, e2.PreviousHash);
        Assert.True(second.Verify());
    }

    public void Dispose()
    {
        try { if (Directory.Exists(_dir)) Directory.Delete(_dir, true); } catch { }
    }
}
