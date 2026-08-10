using System;
using System.Windows;
using Microsoft.Extensions.DependencyInjection;
using LogAnalyzer.Core.Interfaces;
using LogAnalyzer.Core.Services;
using LogAnalyzer.Infrastructure;
using LogAnalyzer.UI.ViewModels;
using LogAnalyzer.UI.Views;

namespace LogAnalyzer.UI
{
    public partial class App : Application
    {
        public static IServiceProvider? ServiceProvider { get; private set; }

        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            this.DispatcherUnhandledException += (sender, args) =>
            {
                MessageBox.Show($"Eroare critică internă:\n{args.Exception.Message}", "Crash", MessageBoxButton.OK, MessageBoxImage.Error);
                args.Handled = true;
            };

            var services = new ServiceCollection();
            
            // Servicii Core (Utilitare)
            services.AddSingleton<AuditLogService>();
            services.AddSingleton<PluginManagerService>();
            services.AddSingleton<KnowledgeBaseService>();
            
            // Motoarele din Infrastructure (Aici se rezolvă eroarea CS0246)
            services.AddSingleton<IEventParser, EvtxParser>();
            services.AddSingleton<IAnalysisEngine, AnalysisEngine>();
            services.AddSingleton<IRegistryParser, RegistryParser>();
            
            // Componentele MVVM din UI
            services.AddTransient<MainViewModel>();
            services.AddTransient<MainWindow>();

            ServiceProvider = services.BuildServiceProvider();

            // Afișăm fereastra principală
            var mainWindow = ServiceProvider.GetRequiredService<MainWindow>();
            mainWindow.Show();
        }
    }
}