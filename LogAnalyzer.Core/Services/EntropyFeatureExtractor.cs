using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text;

namespace LogAnalyzer.Core.Services
{
    public class EntropyAnalysisResult
    {
        public double ShannonEntropy { get; set; }
        public double CompressionRatio { get; set; } // Raport Deflate: compressed / original (< 0.50 = date repetitive; > 0.85 pe text lung = compresie/cifrare ridicată)
        public double NonAlphanumericDensity { get; set; } // Procent caractere non-alfanumerice (-, _, $, +, /, =)
        public bool IsLikelyObfuscated { get; set; }
        public string ObfuscationKind { get; set; } = "Normal Text";
        public string RiskScoreLevel { get; set; } = "Low";
    }

    public class EntropyFeatureExtractor
    {
        /// <summary>
        /// Extrage vectorul de trăsături de complexitate și de-obfuscare din scripturi PowerShell (EID 4104) sau comenzi CLI (EID 4688).
        /// </summary>
        public EntropyAnalysisResult AnalyzeText(string input)
        {
            var result = new EntropyAnalysisResult();
            if (string.IsNullOrWhiteSpace(input)) return result;

            byte[] bytes = Encoding.UTF8.GetBytes(input);

            // 1. Entropie Shannon (0 - 8 bit/byte)
            result.ShannonEntropy = ComputeShannonEntropy(bytes);

            // 2. Raport de Compresie Deflate (proxy Kolmogorov)
            result.CompressionRatio = ComputeCompressionRatio(bytes);

            // 3. Densitate Caractere Non-Alfanumerice
            int nonAlphaCount = input.Count(c => !char.IsLetterOrDigit(c) && !char.IsWhiteSpace(c));
            result.NonAlphanumericDensity = (double)nonAlphaCount / input.Length;

            // 4. Euristici de Obfuscare
            bool containsBase64Keywords = input.Contains("FromBase64String", StringComparison.OrdinalIgnoreCase) ||
                                          input.Contains("-enc", StringComparison.OrdinalIgnoreCase) ||
                                          input.Contains("IEX", StringComparison.OrdinalIgnoreCase) ||
                                          input.Contains("[Convert]", StringComparison.OrdinalIgnoreCase);

            bool highEntropy = result.ShannonEntropy > 5.0 && input.Length > 50;
            bool highNonAlpha = result.NonAlphanumericDensity > 0.25 && input.Length > 30;
            bool highCompression = result.CompressionRatio > 0.80 && input.Length > 80;

            if (containsBase64Keywords && (highEntropy || result.NonAlphanumericDensity > 0.15))
            {
                result.IsLikelyObfuscated = true;
                result.ObfuscationKind = "Payload Obfuscat Base64 / IEX Invocation";
                result.RiskScoreLevel = "Critical";
            }
            else if (highEntropy && highCompression)
            {
                result.IsLikelyObfuscated = true;
                result.ObfuscationKind = "Payload Cifrat / Comprimat cu Entropie Mare";
                result.RiskScoreLevel = "High";
            }
            else if (highNonAlpha)
            {
                result.IsLikelyObfuscated = true;
                result.ObfuscationKind = "Obfuscare Sintactică cu Caractere Speciale / Backticks";
                result.RiskScoreLevel = "Medium";
            }

            return result;
        }

        private static double ComputeShannonEntropy(byte[] data)
        {
            if (data == null || data.Length == 0) return 0.0;

            var freq = new int[256];
            foreach (byte b in data) freq[b]++;

            double entropy = 0.0;
            double len = data.Length;

            for (int i = 0; i < 256; i++)
            {
                if (freq[i] > 0)
                {
                    double p = freq[i] / len;
                    entropy -= p * Math.Log2(p);
                }
            }

            return Math.Round(entropy, 2);
        }

        private static double ComputeCompressionRatio(byte[] data)
        {
            if (data == null || data.Length == 0) return 0.0;

            using var outputStream = new MemoryStream();
            using (var deflateStream = new DeflateStream(outputStream, CompressionLevel.Optimal))
            {
                deflateStream.Write(data, 0, data.Length);
            }

            byte[] compressed = outputStream.ToArray();
            return Math.Round((double)compressed.Length / data.Length, 2);
        }
    }
}
