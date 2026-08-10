using System.Windows;
using LogAnalyzer.Core.Models;
using LogAnalyzer.Core.Services;

namespace LogAnalyzer.UI.Views
{
    public partial class AlertDetailWindow : Window
    {
        public AlertDetailWindow(DetectedIssue alert, AuditLogService audit)
        {
            InitializeComponent();
            TitleBlock.Text = $"[{alert.Severity.ToUpper()}] {alert.Title}";
            DetailsTextBox.Text = $"Tehnică MITRE: {alert.MitreTechniqueId}\n" +
                                  $"Cadru Normativ / Compliance: {alert.ComplianceTag}\n\n" +
                                  $"Explicație Tehnică:\n{alert.Explanation}";
            
            audit.LogAction("ALERT_VIEWED", $"Analistul a investigat alerta: {alert.Title}");
        }

        private void Close_Click(object sender, RoutedEventArgs e) => this.Close();
    }
}