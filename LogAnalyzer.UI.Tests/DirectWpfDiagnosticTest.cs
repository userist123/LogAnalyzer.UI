using System;
using System.IO;
using System.Threading;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Services;
using LogAnalyzer.Infrastructure;
using LogAnalyzer.Infrastructure.Parsers;
using LogAnalyzer.Infrastructure.Services;
using LogAnalyzer.UI.ViewModels;
using LogAnalyzer.UI.Services;
using LogAnalyzer.UI.Views;
using Xunit;

namespace LogAnalyzer.UI.Tests
{
    public class DirectWpfDiagnosticTest
    {
        [Fact]
        public void Diagnose_MainWindow_And_Views_Instantiation()
        {
            Exception caught = null;
            var t = new Thread(() =>
            {
                try
                {
                    if (Application.Current == null)
                    {
                        var app = new Application();
                        var theme = new ResourceDictionary
                        {
                            Source = new Uri("pack://application:,,,/LogAnalyzer.UI;component/Themes/DarkForensicTheme.xaml", UriKind.Absolute)
                        };
                        app.Resources.MergedDictionaries.Add(theme);
                    }

                    var services = new ServiceCollection();
                    services.AddSingleton<AuditLogService>();
                    services.AddSingleton<PluginManagerService>();
                    services.AddSingleton<KnowledgeBaseService>();
                    services.AddSingleton<LogAnalyzer.Core.Services.LicenseService>();
                    var appData = Path.Combine(Path.GetTempPath(), "LogAnalyzerTest");
                    Directory.CreateDirectory(appData);
                    services.AddSingleton<SecurePathService>();
                    services.AddSingleton(sp => new ChainOfCustodyService(Path.Combine(appData, "coc.ndjson")));
                    services.AddSingleton<EvidenceIntakeService>();
                    services.AddSingleton<IEventParser, EvtxParser>();
                    services.AddSingleton<IAnalysisEngine, AnalysisEngine>();
                    services.AddSingleton<IRegistryParser, OfflineRegistryParser>();
                    services.AddSingleton<IDatabaseService, DatabaseService>();
                    services.AddSingleton<IAuditCollectionService, AuditCollectionService>();
                    services.AddTransient<MainViewModel>();
                    services.AddTransient<MainWindow>();

                    var sp = services.BuildServiceProvider();
                    var db = sp.GetRequiredService<IDatabaseService>();
                    db.InitializeDatabase();

                    var vm = sp.GetRequiredService<MainViewModel>();
                    var win = new MainWindow(vm);
                    win.Measure(new Size(1920, 1080));
                    win.Arrange(new Rect(0, 0, 1920, 1080));
                    win.UpdateLayout();
                }
                catch (Exception ex)
                {
                    caught = ex;
                }
            });

            t.SetApartmentState(ApartmentState.STA);
            t.Start();
            t.Join(15000);

            if (caught != null)
            {
                Assert.Fail($"Diagnostic failed:\n{caught}");
            }
        }
    }
}
