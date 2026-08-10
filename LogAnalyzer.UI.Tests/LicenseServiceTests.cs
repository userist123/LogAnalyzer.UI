using System;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using LogAnalyzer.UI.Services;
using Xunit;

namespace LogAnalyzer.UI.Tests;

public sealed class LicenseServiceTests
{
    private static string Base64Url(byte[] data) => Convert.ToBase64String(data).Replace('+', '-').Replace('/', '_').TrimEnd('=');

    private static (string payload, string signature, string publicKeyPem) CreateSignedLicense(string hardwareId, DateTimeOffset expiresAt)
    {
        using var rsa = RSA.Create(2048);
        var payload = new LicensePayload("LIC-001", hardwareId, expiresAt, "LogAnalyzer.UI", "Enterprise");
        var payloadBytes = Encoding.UTF8.GetBytes(JsonSerializer.Serialize(payload));
        var signature = rsa.SignData(payloadBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
        return (Base64Url(payloadBytes), Base64Url(signature), rsa.ExportRSAPublicKeyPem());
    }

    [Fact]
    public void ValidLicense_Passes()
    {
        var hwId = "hw-test-123";
        var (payload, signature, publicKeyPem) = CreateSignedLicense(hwId, DateTimeOffset.UtcNow.AddDays(30));
        var service = new LicenseService(publicKeyPem);
        Assert.True(service.Validate(payload, signature, hwId, out var license));
        Assert.NotNull(license);
        Assert.Equal(hwId, license!.HardwareId);
    }

    [Fact]
    public void WrongHardwareId_Fails()
    {
        var (payload, signature, publicKeyPem) = CreateSignedLicense("hw-1", DateTimeOffset.UtcNow.AddDays(30));
        var service = new LicenseService(publicKeyPem);
        Assert.False(service.Validate(payload, signature, "hw-different", out _));
    }

    [Fact]
    public void ExpiredLicense_Fails()
    {
        var hwId = "hw-test";
        var (payload, signature, publicKeyPem) = CreateSignedLicense(hwId, DateTimeOffset.UtcNow.AddDays(-1));
        var service = new LicenseService(publicKeyPem);
        Assert.False(service.Validate(payload, signature, hwId, out _));
    }

    [Fact]
    public void TamperedSignature_Fails()
    {
        var hwId = "hw-test";
        var (payload, _, publicKeyPem) = CreateSignedLicense(hwId, DateTimeOffset.UtcNow.AddDays(30));
        var service = new LicenseService(publicKeyPem);
        Assert.False(service.Validate(payload, "invalidsignature", hwId, out _));
    }
}
