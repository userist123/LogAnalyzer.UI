using System;
using System.Linq;
using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;

namespace LogAnalyzer.Core.Services;

public sealed class LicenseService
{
    private string? _activatedKey;

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

    public bool ValidateAndSaveKey(string licenseKey)
    {
        if (string.IsNullOrWhiteSpace(licenseKey) || licenseKey.Trim().Length != 20) return false;
        _activatedKey = licenseKey.Trim();
        return true;
    }

    public bool IsActivated => !string.IsNullOrEmpty(_activatedKey);
}
