using System;
using System.Security.Cryptography;
using System.Text.Json;

namespace LogAnalyzer.UI.Services;

public sealed record LicensePayload(string LicenseId, string HardwareId, DateTimeOffset ExpiresAt, string Product, string Edition);

public sealed class LicenseService
{
    private readonly RSA _verificationKey;

    public LicenseService(string publicKeyPem)
    {
        _verificationKey = RSA.Create();
        _verificationKey.ImportFromPem(publicKeyPem);
    }

    public bool Validate(string payloadBase64Url, string signatureBase64Url, string expectedHardwareId, out LicensePayload? license)
    {
        license = null;
        try
        {
            var payloadBytes = Base64UrlDecode(payloadBase64Url);
            var signature = Base64UrlDecode(signatureBase64Url);
            if (!_verificationKey.VerifyData(payloadBytes, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss)) return false;
            license = JsonSerializer.Deserialize<LicensePayload>(payloadBytes);
            return license is not null && license.Product == "LogAnalyzer.UI" && license.HardwareId == expectedHardwareId && license.ExpiresAt > DateTimeOffset.UtcNow;
        }
        catch (CryptographicException) { return false; }
        catch (JsonException) { return false; }
    }

    private static byte[] Base64UrlDecode(string value) => Convert.FromBase64String(value.Replace('-', '+').Replace('_', '/') + new string('=', (4 - value.Length % 4) % 4));
}
