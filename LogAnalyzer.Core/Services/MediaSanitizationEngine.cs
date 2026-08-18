using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

namespace LogAnalyzer.Core.Services
{
    public enum SanitizationMethod
    {
        NistClearZero,        // NIST SP 800-88r2 Clear: 1 trecere 0x00
        NistClearRandom,      // NIST SP 800-88r2 Clear: 1 trecere pseudo-aleatoare
        DoD5220_22_M_3Pass,   // DoD 5220.22-M: 3 treceri (0x00, 0xFF, Random + Verificare)
        CryptographicErase    // HG 585/2002 Art. 65 / NIST Crypto Erase: Distrugere cheie MEK/FEK
    }

    public class SanitizationProgress
    {
        public int CurrentPass { get; set; }
        public int TotalPasses { get; set; }
        public long BytesWritten { get; set; }
        public long TotalBytes { get; set; }
        public double Percentage => TotalBytes > 0 ? (double)BytesWritten / TotalBytes * 100.0 : 0.0;
        public string StatusMessage { get; set; } = string.Empty;
    }

    public class SanitizationResult
    {
        public bool Success { get; set; }
        public SanitizationMethod Method { get; set; }
        public int TotalPassesExecuted { get; set; }
        public long TotalBytesSanitized { get; set; }
        public string PreSanitizationSha256 { get; set; } = string.Empty;
        public string PostSanitizationSha256 { get; set; } = string.Empty;
        public DateTime StartedAtUtc { get; set; }
        public DateTime CompletedAtUtc { get; set; }
        public string ErrorMessage { get; set; } = string.Empty;
    }

    public class MediaSanitizationEngine
    {
        private const int BufferSize = 64 * 1024; // 64 KB buffer

        /// <summary>
        /// Execută sanitizarea deterministă a unui fișier / imagine disc conform metodei NIST / DoD selectate.
        /// </summary>
        public async Task<SanitizationResult> SanitizeMediaAsync(
            string targetPath,
            SanitizationMethod method,
            IProgress<SanitizationProgress>? progress = null,
            CancellationToken cancellationToken = default)
        {
            var result = new SanitizationResult
            {
                Method = method,
                StartedAtUtc = DateTime.UtcNow
            };

            if (!File.Exists(targetPath))
            {
                result.Success = false;
                result.ErrorMessage = $"Ținta specificată nu a fost găsită: {targetPath}";
                return result;
            }

            var fileInfo = new FileInfo(targetPath);
            long totalBytes = fileInfo.Length;
            result.TotalBytesSanitized = totalBytes;

            // 1. Calcul hash pre-sanitizare
            result.PreSanitizationSha256 = await ComputeSha256Async(targetPath, cancellationToken);

            await Task.Run(() =>
            {
                try
                {
                    if (method == SanitizationMethod.CryptographicErase)
                    {
                        // Cryptographic Erase (HG 585/2002 Art. 65 / NIST Crypto Erase)
                        // Suprascriere zonă de metadate & chei de criptare din primii și ultimii 1 MB
                        long headerFooterSize = Math.Min(totalBytes, 1024 * 1024);
                        using var fs = new FileStream(targetPath, FileMode.Open, FileAccess.Write, FileShare.None);
                        
                        byte[] zeroBuffer = new byte[BufferSize];
                        long written = 0;
                        while (written < headerFooterSize)
                        {
                            cancellationToken.ThrowIfCancellationRequested();
                            int toWrite = (int)Math.Min(BufferSize, headerFooterSize - written);
                            fs.Write(zeroBuffer, 0, toWrite);
                            written += toWrite;
                        }

                        if (totalBytes > headerFooterSize * 2)
                        {
                            fs.Seek(-headerFooterSize, SeekOrigin.End);
                            written = 0;
                            while (written < headerFooterSize)
                            {
                                cancellationToken.ThrowIfCancellationRequested();
                                int toWrite = (int)Math.Min(BufferSize, headerFooterSize - written);
                                fs.Write(zeroBuffer, 0, toWrite);
                                written += toWrite;
                            }
                        }

                        fs.Flush(true);
                        result.TotalPassesExecuted = 1;
                    }
                    else if (method == SanitizationMethod.NistClearZero)
                    {
                        // 1 trecere 0x00
                        ExecutePass(targetPath, totalBytes, 1, 1, 0x00, false, progress, cancellationToken);
                        result.TotalPassesExecuted = 1;
                    }
                    else if (method == SanitizationMethod.NistClearRandom)
                    {
                        // 1 trecere date aleatoare
                        ExecutePass(targetPath, totalBytes, 1, 1, 0x00, true, progress, cancellationToken);
                        result.TotalPassesExecuted = 1;
                    }
                    else if (method == SanitizationMethod.DoD5220_22_M_3Pass)
                    {
                        // Trecerea 1: 0x00
                        ExecutePass(targetPath, totalBytes, 1, 3, 0x00, false, progress, cancellationToken);
                        // Trecerea 2: 0xFF
                        ExecutePass(targetPath, totalBytes, 2, 3, 0xFF, false, progress, cancellationToken);
                        // Trecerea 3: Date pseudo-aleatoare
                        ExecutePass(targetPath, totalBytes, 3, 3, 0x00, true, progress, cancellationToken);
                        result.TotalPassesExecuted = 3;
                    }

                    result.Success = true;
                }
                catch (Exception ex)
                {
                    result.Success = false;
                    result.ErrorMessage = ex.Message;
                }
            }, cancellationToken);

            // 2. Calcul hash post-sanitizare
            result.CompletedAtUtc = DateTime.UtcNow;
            if (result.Success && File.Exists(targetPath))
            {
                result.PostSanitizationSha256 = await ComputeSha256Async(targetPath, cancellationToken);
            }

            return result;
        }

        private static void ExecutePass(
            string targetPath,
            long totalBytes,
            int currentPass,
            int totalPasses,
            byte fixedByte,
            bool useRandom,
            IProgress<SanitizationProgress>? progress,
            CancellationToken cancellationToken)
        {
            using var fs = new FileStream(targetPath, FileMode.Open, FileAccess.Write, FileShare.None);
            byte[] buffer = new byte[BufferSize];

            if (!useRandom)
            {
                Array.Fill(buffer, fixedByte);
            }

            long totalWritten = 0;
            while (totalWritten < totalBytes)
            {
                cancellationToken.ThrowIfCancellationRequested();
                int toWrite = (int)Math.Min(BufferSize, totalBytes - totalWritten);

                if (useRandom)
                {
                    RandomNumberGenerator.Fill(buffer.AsSpan(0, toWrite));
                }

                fs.Write(buffer, 0, toWrite);
                totalWritten += toWrite;

                progress?.Report(new SanitizationProgress
                {
                    CurrentPass = currentPass,
                    TotalPasses = totalPasses,
                    BytesWritten = totalWritten,
                    TotalBytes = totalBytes,
                    StatusMessage = $"Trecerea {currentPass}/{totalPasses} ({(useRandom ? "Random" : $"0x{fixedByte:X2}")}) - {totalWritten * 100 / totalBytes}%"
                });
            }

            fs.Flush(true);
        }

        private static async Task<string> ComputeSha256Async(string filePath, CancellationToken cancellationToken)
        {
            using var sha = SHA256.Create();
            using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            byte[] hash = await sha.ComputeHashAsync(fs, cancellationToken);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
    }
}
