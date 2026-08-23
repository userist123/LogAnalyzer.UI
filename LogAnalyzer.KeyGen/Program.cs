using System;
using System.Globalization;
using System.IO;
using System.Management;
using System.Security.Cryptography;
using System.Text;

namespace LogAnalyzer.KeyGen;

public static class Program
{
    private const string Salt = "INFOSEC_ROMANIA_SOC_2026_SECURE_KEY";

    public static void Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.ForegroundColor = ConsoleColor.Cyan;
        Console.WriteLine("===================================================================");
        Console.WriteLine(" 🛡️ LOGANALYZER DFIR ENTERPRISE — KEY GENERATOR & LICENSE MANAGER");
        Console.WriteLine("===================================================================");
        Console.ResetColor();

        if (args.Length == 1 && (args[0] == "--help" || args[0] == "-h"))
        {
            ShowUsage();
            return;
        }

        string hardwareId;
        string expiryInput;

        if (args.Length >= 2)
        {
            hardwareId = args[0].Trim().ToUpperInvariant();
            expiryInput = args[1].Trim();
        }
        else
        {
            var localHwId = GetLocalHardwareId();
            Console.WriteLine($"[+] Hardware ID detectat pe stația locală: {localHwId}");
            Console.Write($"Introduceți Hardware ID [Apăsați ENTER pentru cel local '{localHwId}']: ");
            var inputHw = Console.ReadLine()?.Trim();
            hardwareId = string.IsNullOrWhiteSpace(inputHw) ? localHwId : inputHw.ToUpperInvariant();

            Console.WriteLine();
            Console.WriteLine("Selectați perioada de valabilitate:");
            Console.WriteLine("  1. 1 An (Recomandat Standard)");
            Console.WriteLine("  2. 3 Ani (Enterprise Multi-Year)");
            Console.WriteLine("  3. 10 Ani (Long-Term Air-Gapped Station)");
            Console.WriteLine("  4. Dată Personalizată (Format: YYYY-MM-DD)");
            Console.Write("Alegere [1]: ");
            var choice = Console.ReadLine()?.Trim();

            expiryInput = choice switch
            {
                "2" => DateTime.UtcNow.AddYears(3).ToString("yyyy-MM-dd"),
                "3" => DateTime.UtcNow.AddYears(10).ToString("yyyy-MM-dd"),
                "4" => PromptCustomDate(),
                _ => DateTime.UtcNow.AddYears(1).ToString("yyyy-MM-dd")
            };
        }

        if (string.IsNullOrWhiteSpace(hardwareId) || hardwareId.Length < 8)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[-] Eroare: Hardware ID invalid (trebuie să conțină minim 8 caractere hexazecimale).");
            Console.ResetColor();
            Environment.ExitCode = 1;
            return;
        }

        if (!DateTime.TryParseExact(expiryInput.Trim(), "yyyy-MM-dd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var expiryDate))
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[-] Eroare: Formatul datei trebuie să fie strict YYYY-MM-DD (ex: 2027-12-31).");
            Console.ResetColor();
            Environment.ExitCode = 1;
            return;
        }

        var datePart = expiryDate.ToString("yyyyMMdd");
        var payload = $"{hardwareId.Trim().ToUpperInvariant()}{datePart}{Salt}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(payload));
        var key = Convert.ToHexString(hash)[..20];
        var fullLicenseString = $"{key}|{expiryDate:yyyy-MM-dd}";

        Console.WriteLine();
        Console.ForegroundColor = ConsoleColor.Green;
        Console.WriteLine("===================================================================");
        Console.WriteLine(" ✅ LICENȚĂ GENERATĂ CU SUCCES:");
        Console.WriteLine("===================================================================");
        Console.WriteLine($" Target Hardware ID: {hardwareId}");
        Console.WriteLine($" Valabilitate până:  {expiryDate:yyyy-MM-dd}");
        Console.WriteLine($" Cheie Criptografică:{key}");
        Console.WriteLine($" Șir Licență:        {fullLicenseString}");
        Console.WriteLine("===================================================================");
        Console.ResetColor();

        Console.WriteLine();
        Console.Write("Doriți să salvați licența în fișierul 'license.lic'? [D/n]: ");
        var saveChoice = Console.ReadLine()?.Trim().ToUpperInvariant();
        if (string.IsNullOrEmpty(saveChoice) || saveChoice == "D" || saveChoice == "Y" || saveChoice == "DA")
        {
            File.WriteAllText("license.lic", fullLicenseString, Encoding.UTF8);
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine($"[+] Fișierul '{Path.GetFullPath("license.lic")}' a fost salvat cu succes!");
            Console.ResetColor();
        }
    }

    private static string PromptCustomDate()
    {
        Console.Write("Introduceți data de expirare (YYYY-MM-DD): ");
        return Console.ReadLine()?.Trim() ?? DateTime.UtcNow.AddYears(1).ToString("yyyy-MM-dd");
    }

    private static string GetLocalHardwareId()
    {
        try
        {
            string cpuId = string.Empty;
            string boardSerial = string.Empty;

            using (var searcher = new ManagementObjectSearcher("SELECT ProcessorId FROM Win32_Processor"))
            {
                foreach (var obj in searcher.Get())
                {
                    cpuId = obj["ProcessorId"]?.ToString() ?? string.Empty;
                    if (!string.IsNullOrEmpty(cpuId)) break;
                }
            }

            using (var searcher = new ManagementObjectSearcher("SELECT SerialNumber FROM Win32_BaseBoard"))
            {
                foreach (var obj in searcher.Get())
                {
                    boardSerial = obj["SerialNumber"]?.ToString() ?? string.Empty;
                    if (!string.IsNullOrEmpty(boardSerial)) break;
                }
            }

            var combined = $"{cpuId}_{boardSerial}_{Environment.MachineName}";
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(combined));
            return Convert.ToHexString(hash)[..16].ToUpperInvariant();
        }
        catch
        {
            return "DEFAULT_HWID_0000";
        }
    }

    private static void ShowUsage()
    {
        Console.WriteLine("Utilizare:");
        Console.WriteLine("  LogAnalyzer.KeyGen [<HARDWARE_ID>] [<YYYY-MM-DD>]");
        Console.WriteLine();
        Console.WriteLine("Exemple:");
        Console.WriteLine("  LogAnalyzer.KeyGen");
        Console.WriteLine("  LogAnalyzer.KeyGen ABCD1234EFGH5678 2027-12-31");
    }
}
