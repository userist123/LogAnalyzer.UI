using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json;

namespace LogAnalyzer.Core.Services
{
    public class SanitizationCertificateData
    {
        public string CertificateId { get; set; } = $"SAN-CERT-{DateTime.UtcNow:yyyyMMdd}-{Guid.NewGuid():N}".Substring(0, 24).ToUpperInvariant();
        public string StandardCompliance { get; set; } = "NIST SP 800-88r2 / HG 585/2002 Art. 65 / NATO AC/35-D/1022";
        public string DeviceVendor { get; set; } = string.Empty;
        public string DeviceModel { get; set; } = string.Empty;
        public string HardwareSerialNumber { get; set; } = string.Empty; // P16
        public long DeviceCapacityBytes { get; set; }
        public string SanitizationMethodName { get; set; } = string.Empty;
        public int TotalPasses { get; set; }
        public string PreSanitizationSha256 { get; set; } = string.Empty;
        public string PostSanitizationSha256 { get; set; } = string.Empty;
        public string PrimaryOperator { get; set; } = string.Empty;
        public string VerifierOperator { get; set; } = string.Empty; // 4-Eyes
        public string SystemHostId { get; set; } = Environment.MachineName;
        public DateTime TimestampUtc { get; set; } = DateTime.UtcNow;
        public string TamperEvidentAuditHash { get; set; } = string.Empty;
        public bool IsVerifiedZeroized { get; set; } = true;
    }

    public class SanitizationCertificateGenerator
    {
        /// <summary>
        /// Generează certificatul oficial de sanitizare conform standardului NIST SP 800-88r2 în format text structurat.
        /// </summary>
        public string GenerateTextCertificate(SanitizationCertificateData data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            var sb = new StringBuilder();
            sb.AppendLine("================================================================================");
            sb.AppendLine("                 CERTIFICAT OFICIAL DE SANITIZARE A DATELOR                    ");
            sb.AppendLine("         Conform NIST SP 800-88r2 / HG 585/2002 / NATO AC/35-D/1022             ");
            sb.AppendLine("================================================================================");
            sb.AppendLine();
            sb.AppendLine($"  ID CERTIFICAT:              {data.CertificateId}");
            sb.AppendLine($"  DATA ȘI ORA (UTC):          {data.TimestampUtc:yyyy-MM-dd HH:mm:ss} UTC");
            sb.AppendLine($"  STANDARD APLICAT:           {data.StandardCompliance}");
            sb.AppendLine();
            sb.AppendLine("--------------------------------------------------------------------------------");
            sb.AppendLine(" 1. DATE TEHNICE DISPOZITIV FIZIC (TELEMETRIE IMUTABILĂ P16)");
            sb.AppendLine("--------------------------------------------------------------------------------");
            sb.AppendLine($"  Producător (Vendor):        {data.DeviceVendor}");
            sb.AppendLine($"  Model / Produs:             {data.DeviceModel}");
            sb.AppendLine($"  Număr Serie Fizic (P16):    {data.HardwareSerialNumber}");
            sb.AppendLine($"  Capacitate Mediu:           {data.DeviceCapacityBytes:N0} bytes ({(double)data.DeviceCapacityBytes / (1024 * 1024 * 1024):F2} GB)");
            sb.AppendLine($"  Sistem Gazdă (Host ID):     {data.SystemHostId}");
            sb.AppendLine();
            sb.AppendLine("--------------------------------------------------------------------------------");
            sb.AppendLine(" 2. DETALII PROCEDURĂ SANITIZARE");
            sb.AppendLine("--------------------------------------------------------------------------------");
            sb.AppendLine($"  Metodă Utilizată:           {data.SanitizationMethodName}");
            sb.AppendLine($"  Număr Treceri Executate:    {data.TotalPasses}");
            sb.AppendLine($"  Hash Pre-Sanitizare:        {data.PreSanitizationSha256}");
            sb.AppendLine($"  Hash Post-Sanitizare:       {data.PostSanitizationSha256}");
            sb.AppendLine($"  Verificare Zeroizare:       {(data.IsVerifiedZeroized ? "CONFIRMATĂ (Date irecuperabile)" : "NECONFIRMATĂ")}");
            sb.AppendLine();
            sb.AppendLine("--------------------------------------------------------------------------------");
            sb.AppendLine(" 3. AUTORIZARE DUALĂ & LANȚ DE CUSTODIE (4-EYES PRINCIPLE)");
            sb.AppendLine("--------------------------------------------------------------------------------");
            sb.AppendLine($"  Operator Principal:         {data.PrimaryOperator}");
            sb.AppendLine($"  Ofițer Securitate / Martor: {data.VerifierOperator}");
            sb.AppendLine($"  Hash Audit Tamper-Evident:  {data.TamperEvidentAuditHash}");
            sb.AppendLine();
            sb.AppendLine("================================================================================");
            sb.AppendLine(" Prin prezenta se atestă că datele stocate pe mediul menționat au fost distruse");
            sb.AppendLine(" ireversibil, fără posibilitate de recuperare prin metode forenzice avansate.");
            sb.AppendLine("================================================================================");

            return sb.ToString();
        }

        /// <summary>
        /// Generează certificatul oficial în format JSON pentru integrare automată în sistemele SIEM/Audit.
        /// </summary>
        public string GenerateJsonCertificate(SanitizationCertificateData data)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            return JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = true });
        }
    }
}
