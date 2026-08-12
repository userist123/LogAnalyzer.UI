using System;
using System.IO;
using System.Management;
using System.Security.Cryptography;
using System.Text;

namespace LogAnalyzer.Core.Services
{
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
            return CalculateSha256(rawId).Substring(0, 16).ToUpper();
        }

        // Generhează cheia ținând cont de Hardware ID și data de expirare
        public string GenerateKey(string hwId, DateTime expiryDate)
        {
            string datePart = expiryDate.ToString("yyyyMMdd");
            return CalculateSha256(hwId.Trim().ToUpper() + datePart + _salt).Substring(0, 20).ToUpper();
        }

        // Validează formatul introdus de client: "CHEIE|AAAA-LL-ZZ"
        public bool ValidateAndSaveKey(string fullInput)
        {
            try
            {
                var parts = fullInput.Trim().Split('|');
                if (parts.Length != 2) return false;

                string inputKey = parts[0].Trim();
                if (!DateTime.TryParse(parts[1], out DateTime expiryDate)) return false;

                // Verificăm dacă licența introdusă nu este deja expirată
                if (DateTime.UtcNow > expiryDate) return false;

                string hwId = GetHardwareId();
                string expectedKey = GenerateKey(hwId, expiryDate);

                if (inputKey.Equals(expectedKey, StringComparison.OrdinalIgnoreCase))
                {
                    // Salvăm întregul șir (Cheie + Dată) în fișierul licenței
                    File.WriteAllText(_licenseFilePath, fullInput.Trim());
                    return true;
                }
            }
            catch { }

            return false;
        }

        // Verifică la fiecare pornire dacă licența este validă și în termen
        public bool IsActivated()
        {
            if (!File.Exists(_licenseFilePath)) return false;

            try
            {
                string content = File.ReadAllText(_licenseFilePath).Trim();
                var parts = content.Split('|');
                if (parts.Length != 2) return false;

                string savedKey = parts[0].Trim();
                if (!DateTime.TryParse(parts[1], out DateTime expiryDate)) return false;

                // Dacă data curentă a depășit data de expirare, licența devine invalida
                if (DateTime.UtcNow > expiryDate) return false;

                string hwId = GetHardwareId();
                string expectedKey = GenerateKey(hwId, expiryDate);

                return savedKey.Equals(expectedKey, StringComparison.OrdinalIgnoreCase);
            }
            catch
            {
                return false;
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
            catch { }
            return "UNKNOWN_HW_ID_001";
        }

        private string CalculateSha256(string rawData)
        {
            using var sha256 = SHA256.Create();
            byte[] bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(rawData));
            return BitConverter.ToString(bytes).Replace("-", "").ToLowerInvariant();
        }
    }
}