using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using LogAnalyzer.Core.Interfaces;

namespace LogAnalyzer.Infrastructure.Services
{
    public class AuditCollectionService : IAuditCollectionService
    {
        private UdpClient? _udpListener;
        private CancellationTokenSource? _syslogCts;
        private bool _isActive;

        public bool IsSyslogListenerActive => _isActive;

        public async Task RunCollectionAsync(string targetType, string outputDir, string hostname, Action<string> logCallback)
        {
            await Task.Run(() =>
            {
                try
                {
                    string scriptPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "Scripts", "AuditCollector.ps1");
                    
                    // Fallback în caz că folderul Scripts este în rădăcina proiectului, nu în bin
                    if (!File.Exists(scriptPath))
                    {
                        scriptPath = Path.Combine("C:\\Users\\Marius\\Desktop\\LogAnalyzer.MVP\\Scripts", "AuditCollector.ps1");
                    }

                    if (!File.Exists(scriptPath))
                    {
                        logCallback($"[ERROR] Scriptul de colectare nu a fost găsit la calea: {scriptPath}");
                        return;
                    }

                    logCallback($"[INIT] Pornire colectare pentru [{targetType}] pe host-ul [{hostname}]...");
                    logCallback($"[INIT] Script rulat: {scriptPath}");
                    logCallback($"[INIT] Destinație: {outputDir}");

                    var startInfo = new ProcessStartInfo
                    {
                        FileName = "powershell.exe",
                        Arguments = $"-NoProfile -ExecutionPolicy Bypass -File \"{scriptPath}\" -TargetType \"{targetType}\" -OutputDirectory \"{outputDir}\" -Hostname \"{hostname}\"",
                        UseShellExecute = false,
                        RedirectStandardOutput = true,
                        RedirectStandardError = true,
                        CreateNoWindow = true
                    };

                    using var process = new Process { StartInfo = startInfo };
                    
                    process.OutputDataReceived += (s, e) =>
                    {
                        if (e.Data != null) logCallback(e.Data);
                    };

                    process.ErrorDataReceived += (s, e) =>
                    {
                        if (e.Data != null) logCallback($"[STDERR] {e.Data}");
                    };

                    process.Start();
                    process.BeginOutputReadLine();
                    process.BeginErrorReadLine();
                    process.WaitForExit();

                    logCallback($"[SUCCESS] Procesul de colectare s-a încheiat cu codul de ieșire: {process.ExitCode}");
                }
                catch (Exception ex)
                {
                    logCallback($"[ERROR] Excepție la rularea scriptului: {ex.Message}");
                }
            });
        }

        public void StartSyslogListener(int port, string outputDir, string hostname, Action<string> logCallback)
        {
            if (_isActive)
            {
                logCallback("[WARN] Ascultătorul Syslog este deja activ.");
                return;
            }

            _syslogCts = new CancellationTokenSource();
            _isActive = true;
            
            var token = _syslogCts.Token;

            Task.Run(async () =>
            {
                try
                {
                    _udpListener = new UdpClient(port);
                    logCallback($"[SYSLOG] Ascultător UDP pornit pe portul {port} pentru host [{hostname}]...");
                    
                    // Pregătim folderul conform structurii: [OutputDir]\[Month-Year]\[Prefix]_[Hostname]
                    string monthFolder = DateTime.Now.ToString("MM-yyyy");
                    string targetFolder = Path.Combine(outputDir, monthFolder, $"DC_{hostname}");
                    Directory.CreateDirectory(targetFolder);
                    
                    string logFileName = $"DC_{hostname}_Syslog_{DateTime.Now:dd-MM-yyyy}.log";
                    string logFilePath = Path.Combine(targetFolder, logFileName);
                    
                    logCallback($"[SYSLOG] Jurnalele vor fi salvate în: {logFilePath}");

                    while (!token.IsCancellationRequested)
                    {
                        var result = await _udpListener.ReceiveAsync(token);
                        string message = Encoding.UTF8.GetString(result.Buffer);
                        string logEntry = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{result.RemoteEndPoint}] {message}";
                        
                        // Scriere imediată în fișier (append)
                        await File.AppendAllTextAsync(logFilePath, logEntry + Environment.NewLine, token);
                        
                        logCallback($"[SYSLOG RECV] {logEntry}");
                    }
                }
                catch (OperationCanceledException)
                {
                    logCallback("[SYSLOG] Ascultătorul a fost oprit.");
                }
                catch (Exception ex)
                {
                    logCallback($"[SYSLOG ERROR] {ex.Message}");
                }
                finally
                {
                    _isActive = false;
                    _udpListener?.Close();
                    _udpListener = null;
                }
            }, token);
        }

        public void StopSyslogListener()
        {
            _syslogCts?.Cancel();
            _udpListener?.Close();
            _isActive = false;
        }
    }
}
