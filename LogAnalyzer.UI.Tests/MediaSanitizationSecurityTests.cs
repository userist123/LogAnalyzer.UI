using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using LogAnalyzer.Core.Services;
using Xunit;

namespace LogAnalyzer.UI.Tests
{
    public class MediaSanitizationSecurityTests
    {
        [Fact]
        public async Task MediaSanitizationEngine_NistClearZero_WipesFileCompletely()
        {
            var engine = new MediaSanitizationEngine();
            string tempFile = Path.Combine(Path.GetTempPath(), $"wipe_test_{Guid.NewGuid():N}.bin");

            try
            {
                // Scriem date confidențiale simulare
                byte[] secretData = Encoding.UTF8.GetBytes("TOP SECRET CLASSIFIED DATA 1234567890 NOT FOR DISTRIBUTION");
                byte[] fullPayload = new byte[1024 * 128]; // 128 KB
                for (int i = 0; i < fullPayload.Length; i += secretData.Length)
                {
                    Array.Copy(secretData, 0, fullPayload, i, Math.Min(secretData.Length, fullPayload.Length - i));
                }
                File.WriteAllBytes(tempFile, fullPayload);

                string preHash = ComputeFileSha256(tempFile);

                var result = await engine.SanitizeMediaAsync(tempFile, SanitizationMethod.NistClearZero);

                Assert.True(result.Success);
                Assert.Equal(1, result.TotalPassesExecuted);
                Assert.Equal(preHash, result.PreSanitizationSha256);
                Assert.NotEqual(result.PreSanitizationSha256, result.PostSanitizationSha256);

                // Verificăm conținutul pe disc: trebuie să fie exclusiv 0x00
                byte[] wipedContent = File.ReadAllBytes(tempFile);
                Assert.Equal(fullPayload.Length, wipedContent.Length);
                foreach (byte b in wipedContent)
                {
                    Assert.Equal(0x00, b);
                }
            }
            finally
            {
                if (File.Exists(tempFile)) File.Delete(tempFile);
            }
        }

        [Fact]
        public async Task MediaSanitizationEngine_DoD3Pass_ExecutesThreePassesAndWipesData()
        {
            var engine = new MediaSanitizationEngine();
            string tempFile = Path.Combine(Path.GetTempPath(), $"dod_wipe_{Guid.NewGuid():N}.bin");

            try
            {
                byte[] dummy = new byte[64 * 1024]; // 64 KB
                RandomNumberGenerator.Fill(dummy);
                File.WriteAllBytes(tempFile, dummy);

                var result = await engine.SanitizeMediaAsync(tempFile, SanitizationMethod.DoD5220_22_M_3Pass);

                Assert.True(result.Success);
                Assert.Equal(3, result.TotalPassesExecuted);
                Assert.NotEmpty(result.PreSanitizationSha256);
                Assert.NotEmpty(result.PostSanitizationSha256);
                Assert.NotEqual(result.PreSanitizationSha256, result.PostSanitizationSha256);
            }
            finally
            {
                if (File.Exists(tempFile)) File.Delete(tempFile);
            }
        }

        [Fact]
        public void SanitizationCertificateGenerator_ProducesValidCertificateWithInvariants()
        {
            var certGen = new SanitizationCertificateGenerator();
            var data = new SanitizationCertificateData
            {
                DeviceVendor = "SanDisk",
                DeviceModel = "Ultra Fit USB 3.1",
                HardwareSerialNumber = "4C53000123456789",
                DeviceCapacityBytes = 32000000000,
                SanitizationMethodName = "NIST SP 800-88r2 Purge (DoD 5220.22-M 3-Pass)",
                TotalPasses = 3,
                PreSanitizationSha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                PostSanitizationSha256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                PrimaryOperator = "OP-MARIUS-01",
                VerifierOperator = "SEC-OFFICER-ALEX",
                TamperEvidentAuditHash = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                IsVerifiedZeroized = true
            };

            string textCert = certGen.GenerateTextCertificate(data);
            string jsonCert = certGen.GenerateJsonCertificate(data);

            Assert.NotNull(textCert);
            Assert.Contains("CERTIFICAT OFICIAL DE SANITIZARE A DATELOR", textCert);
            Assert.Contains("4C53000123456789", textCert); // P16 Serial
            Assert.Contains("OP-MARIUS-01", textCert);
            Assert.Contains("SEC-OFFICER-ALEX", textCert); // 4-Eyes

            Assert.NotNull(jsonCert);
            Assert.Contains("4C53000123456789", jsonCert);
            Assert.Contains("NIST SP 800-88r2", jsonCert);
        }

        private static string ComputeFileSha256(string filePath)
        {
            using var sha = SHA256.Create();
            using var fs = File.OpenRead(filePath);
            return Convert.ToHexString(sha.ComputeHash(fs)).ToLowerInvariant();
        }
    }
}
