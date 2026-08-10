using System;
using System.IO;
using System.Management;
using System.Security.Cryptography;
using System.Text;

namespace LogAnalyzer.Core.Services;

public class LicenseService
{
    private readonly string _licenseFilePath;
    private readonly string _salt = "INFOSEC_ROMANIA_SOC_2026_SECURE_KEY";

    public LicenseService()
    {
        _licenseFilePath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "license.lic");
    }

    public string GetHardwareId()
    {
        string cpuId = GetWmiProperty("Win32_Processor", "ProcessorId");
        string boardId = GetWmiProperty("Win32_BaseBoard", "SerialNumber");
        string rawId = cpuId + boardId;
        return CalculateSha256(rawId).Substring(0, 16).ToUpperInvariant();
    }

    public string GenerateKey(string hwId, DateTime expiryDate)
    {
        string datePart = expiryDate.ToString("yyyyMMdd");
        return CalculateSha256(hwId.Trim().ToUpperInvariant() + datePart + _salt)
            .Substring(0, 20)
            .ToUpperInvariant();
    }

    public bool ValidateAndSaveKey(string fullInput)
    {
        try
        {
            var parts = fullInput.Trim().Split('|');
            if (parts.Length != 2) return false;

            string inputKey = parts[0].Trim();
            if (!DateTime.TryParse(parts[1], out DateTime expiryDate)) return false;
            if (DateTime.UtcNow > expiryDate) return false;

            string expectedKey = GenerateKey(GetHardwareId(), expiryDate);
            if (!inputKey.Equals(expectedKey, StringComparison.OrdinalIgnoreCase)) return false;

            File.WriteAllText(_licenseFilePath, fullInput.Trim());
            return true;
        }
        catch
        {
            return false;
        }
    }

    public bool IsActivated
    {
        get
        {
            if (!File.Exists(_licenseFilePath)) return false;

            try
            {
                string content = File.ReadAllText(_licenseFilePath).Trim();
                var parts = content.Split('|');
                if (parts.Length != 2) return false;

                string savedKey = parts[0].Trim();
                if (!DateTime.TryParse(parts[1], out DateTime expiryDate)) return false;
                if (DateTime.UtcNow > expiryDate) return false;

                string expectedKey = GenerateKey(GetHardwareId(), expiryDate);
                return savedKey.Equals(expectedKey, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
            }
        }
    }

    private string GetWmiProperty(string wmiClass, string property)
    {
        try
        {
            if (OperatingSystem.IsWindows())
            {
                using var searcher = new ManagementObjectSearcher($"SELECT {property} FROM {wmiClass}");
                foreach (var obj in searcher.Get()) return obj[property]?.ToString() ?? "";
            }
        }
        catch
        {
        }

        return "UNKNOWN_HW_ID_001";
    }

    private string CalculateSha256(string rawData)
    {
        using var sha256 = SHA256.Create();
        byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawData));
        return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
    }
}
