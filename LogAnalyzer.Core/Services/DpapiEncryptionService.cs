using System;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace LogAnalyzer.Core.Services
{
    [SupportedOSPlatform("windows")]
    public static class DpapiEncryptionService
    {
        public static string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(plainText)) return string.Empty;

            try
            {
                byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                byte[] encryptedBytes = ProtectedData.Protect(plainBytes, null, DataProtectionScope.CurrentUser);
                return Convert.ToBase64String(encryptedBytes);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Eroare la criptarea DPAPI: {ex.Message}");
            }
        }

        public static string Decrypt(string cipherText)
        {
            if (string.IsNullOrEmpty(cipherText)) return string.Empty;

            try
            {
                byte[] encryptedBytes = FromBase64Safe(cipherText);
                byte[] plainBytes = ProtectedData.Unprotect(encryptedBytes, null, DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(plainBytes);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException($"Eroare la decriptarea DPAPI: {ex.Message}");
            }
        }

        private static byte[] FromBase64Safe(string base64)
        {
            return Convert.FromBase64String(base64);
        }
    }
}