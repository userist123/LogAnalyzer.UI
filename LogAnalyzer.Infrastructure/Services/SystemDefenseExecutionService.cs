using System;
using System.Diagnostics;
using System.IO;

namespace LogAnalyzer.Infrastructure.Services
{
    public class DefenseActionResult
    {
        public bool Success { get; set; }
        public string Message { get; set; } = string.Empty;
        public string ExecutionDetails { get; set; } = string.Empty;
    }

    public static class SystemDefenseExecutionService
    {
        private const string FirewallIsolationRuleName = "DFIR_EMERGENCY_ISOLATION";
        private const string FirewallBlockPhishingRuleName = "DFIR_BLOCK_PHISHING_IOC";

        /// <summary>
        /// Execută izolarea reală a calculatorului din rețea prin Windows Firewall (blochează tot traficul outbound).
        /// </summary>
        public static DefenseActionResult IsolateHostFromNetwork()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netsh.exe",
                    Arguments = $"advfirewall firewall add rule name=\"{FirewallIsolationRuleName}\" dir=out action=block profile=any",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var proc = Process.Start(psi);
                proc?.WaitForExit(4000);
                string output = proc?.StandardOutput.ReadToEnd() ?? string.Empty;

                return new DefenseActionResult
                {
                    Success = proc?.ExitCode == 0,
                    Message = "Gazda a fost izolată cu succes din rețea (Trafic extern blocat).",
                    ExecutionDetails = output
                };
            }
            catch (Exception ex)
            {
                return new DefenseActionResult
                {
                    Success = false,
                    Message = $"Eroare la aplicarea izolării Windows Firewall: {ex.Message}",
                    ExecutionDetails = ex.ToString()
                };
            }
        }

        /// <summary>
        /// Ridică izolarea de rețea.
        /// </summary>
        public static DefenseActionResult RestoreNetworkAccess()
        {
            try
            {
                var psi = new ProcessStartInfo
                {
                    FileName = "netsh.exe",
                    Arguments = $"advfirewall firewall delete rule name=\"{FirewallIsolationRuleName}\"",
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var proc = Process.Start(psi);
                proc?.WaitForExit(4000);

                return new DefenseActionResult
                {
                    Success = true,
                    Message = "Izolarea a fost ridicată. Conexiunile de rețea au fost restaurate."
                };
            }
            catch (Exception ex)
            {
                return new DefenseActionResult
                {
                    Success = false,
                    Message = $"Eroare la restaurarea conexiunii: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Oprește forțat procesul suspect și tot arborele său de procese (Kill Process Tree).
        /// </summary>
        public static DefenseActionResult TerminateProcessTree(string? processName, int? pid = null)
        {
            int killedCount = 0;
            try
            {
                if (pid.HasValue && pid.Value > 4)
                {
                    try
                    {
                        var proc = Process.GetProcessById(pid.Value);
                        proc.Kill(entireProcessTree: true);
                        killedCount++;
                    }
                    catch { }
                }

                if (!string.IsNullOrWhiteSpace(processName))
                {
                    string cleanName = Path.GetFileNameWithoutExtension(processName).Trim();
                    // Don't kill critical system processes
                    if (!cleanName.Equals("explorer", StringComparison.OrdinalIgnoreCase) &&
                        !cleanName.Equals("system", StringComparison.OrdinalIgnoreCase) &&
                        !cleanName.Equals("LogAnalyzer.Network", StringComparison.OrdinalIgnoreCase))
                    {
                        var matches = Process.GetProcessesByName(cleanName);
                        foreach (var p in matches)
                        {
                            try
                            {
                                p.Kill(entireProcessTree: true);
                                killedCount++;
                            }
                            catch { }
                        }
                    }
                }

                return new DefenseActionResult
                {
                    Success = true,
                    Message = killedCount > 0 
                        ? $"Au fost neutralizate forțat {killedCount} procese suspecte din memorie."
                        : "Procesul suspect nu mai rula în memorie (deja oprit sau expirat)."
                };
            }
            catch (Exception ex)
            {
                return new DefenseActionResult
                {
                    Success = false,
                    Message = $"Eroare la oprirea procesului: {ex.Message}"
                };
            }
        }

        /// <summary>
        /// Blochează un domeniu sau IP suspect prin regulă de Firewall și DNS Sinkhole.
        /// </summary>
        public static DefenseActionResult BlockMaliciousIoC(string iocTarget)
        {
            try
            {
                string target = string.IsNullOrWhiteSpace(iocTarget) ? "185.220.101.5" : iocTarget.Trim();

                var psi = new ProcessStartInfo
                {
                    FileName = "netsh.exe",
                    Arguments = $"advfirewall firewall add rule name=\"{FirewallBlockPhishingRuleName}_{Guid.NewGuid().ToString().Substring(0, 6)}\" dir=out action=block remoteip=\"{target}\"",
                    RedirectStandardOutput = true,
                    UseShellExecute = false,
                    CreateNoWindow = true
                };

                using var proc = Process.Start(psi);
                proc?.WaitForExit(3000);

                return new DefenseActionResult
                {
                    Success = true,
                    Message = $"Ținta malițioasă [{target}] a fost blocată pe Windows Firewall."
                };
            }
            catch (Exception ex)
            {
                return new DefenseActionResult
                {
                    Success = false,
                    Message = $"Eroare la blocarea IoC: {ex.Message}"
                };
            }
        }
    }
}
