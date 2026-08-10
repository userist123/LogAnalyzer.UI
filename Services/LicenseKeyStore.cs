using System;
using System.IO;
using System.Text;
using System.Text.Json;

namespace LogAnalyzer.UI.Services;

public sealed record StoredLicense(string PayloadBase64Url, string SignatureBase64Url);

public sealed class LicenseKeyStore
{
    private readonly ProtectedSecretStore _secretStore;
    private readonly string _licensePath;

    public LicenseKeyStore(ProtectedSecretStore secretStore, string licensePath)
    {
        _secretStore = secretStore;
        _licensePath = licensePath;
    }

    public void Save(StoredLicense license)
    {
        var json = JsonSerializer.Serialize(license);
        _secretStore.Protect(_licensePath, Encoding.UTF8.GetBytes(json));
    }

    public StoredLicense? TryLoad()
    {
        if (!File.Exists(_licensePath)) return null;
        var bytes = _secretStore.Unprotect(_licensePath);
        return JsonSerializer.Deserialize<StoredLicense>(Encoding.UTF8.GetString(bytes));
    }

    public bool TryValidate(LicenseService licenseService, string expectedHardwareId, out LicensePayload? license)
    {
        license = null;
        var stored = TryLoad();
        if (stored is null) return false;
        return licenseService.Validate(stored.PayloadBase64Url, stored.SignatureBase64Url, expectedHardwareId, out license);
    }
}
