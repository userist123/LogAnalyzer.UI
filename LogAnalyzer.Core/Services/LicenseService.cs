using System;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;

namespace LogAnalyzer.Core.Services;

public sealed class LicenseService
{
    private readonly string _licenseFilePath;
    private readonly string _salt = "LOGANALYZER_SOC_LICENSE_SALT_2026";
    private string? _activatedKey;

    public LicenseService()
    {
        _licenseFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "license.lic");
        TryLoadPersistedLicense();
    }

    public string GetHardwareId()
    {
        var macs = NetworkInterface.GetAllNetworkInterfaces()
            .Where(n => n.OperationalStatus == OperationalStatus.Up)
            .Select(n => n.GetPhysicalAddress().ToString())
            .Where(x => !string.IsNullOrWhiteSpace(x))
            .OrderBy(x => x, StringComparer.Ordinal)
            .ToArray();

        var material = string.Join("|", Environment.MachineName, string.Join(",", macs));
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToUpperInvariant();
        return hash[..20];
    }

    public string GenerateKey(string hardwareId, DateTime expiryDate)
    {
        var datePart = expiryDate.ToString("yyyyMMdd");
        var material = hardwareId.Trim().ToUpperInvariant() + datePart + _salt;
        var hash = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material))).ToUpperInvariant();
        return hash[..20];
    }

    public bool ValidateAndSaveKey(string fullInput)
    {
        if (!TryParseAndValidate(fullInput, out _)) return false;

        _activatedKey = fullInput.Trim();
        try { File.WriteAllText(_licenseFilePath, _activatedKey); } catch { }
        return true;
    }

    public bool IsActivated => !string.IsNullOrEmpty(_activatedKey);

    private void TryLoadPersistedLicense()
    {
        try
        {
            if (!File.Exists(_licenseFilePath)) return;
            var content = File.ReadAllText(_licenseFilePath).Trim();
            if (TryParseAndValidate(content, out _))
                _activatedKey = content;
        }
        catch
        {
        }
    }

    private bool TryParseAndValidate(string fullInput, out DateTime expiry)
    {
        expiry = default;
        if (string.IsNullOrWhiteSpace(fullInput)) return false;

        var parts = fullInput.Trim().Split('|');
        if (parts.Length != 2) return false;

        var key = parts[0].Trim();
        if (!DateTime.TryParse(parts[1], out expiry)) return false;
        if (DateTime.UtcNow > expiry) return false;

        var expectedKey = GenerateKey(GetHardwareId(), expiry.Date);
        return key.Equals(expectedKey, StringComparison.OrdinalIgnoreCase);
    }
}
