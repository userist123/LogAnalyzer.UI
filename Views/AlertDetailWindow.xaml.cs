using System.Windows;
using System.Windows.Media;
using LogAnalyzer.Core.Models;
using LogAnalyzer.Core.Services;

namespace LogAnalyzer.UI.Views
{
    public partial class AlertDetailWindow : Window
    {
        public AlertDetailWindow(DetectedIssue alert, AuditLogService audit)
        {
            InitializeComponent();
            TitleBlock.Text = alert.Title;
            SeverityText.Text = alert.Severity.ToUpper();
            MitreBlock.Text = string.IsNullOrWhiteSpace(alert.MitreTechniqueId) ? "N/A / General" : alert.MitreTechniqueId;
            ComplianceBlock.Text = string.IsNullOrWhiteSpace(alert.ComplianceTag) ? "N/A" : alert.ComplianceTag;
            DetailsTextBox.Text = alert.Explanation;

            // Dynamically color severity badge
            if (alert.Severity.Equals("Critical", System.StringComparison.OrdinalIgnoreCase) || 
                alert.Severity.Equals("High", System.StringComparison.OrdinalIgnoreCase))
            {
                SeverityBadge.Background = new SolidColorBrush(Color.FromRgb(239, 68, 68)); // DangerRed
            }
            else if (alert.Severity.Equals("Medium", System.StringComparison.OrdinalIgnoreCase))
            {
                SeverityBadge.Background = new SolidColorBrush(Color.FromRgb(245, 158, 11)); // WarningOrange
            }
            else
            {
                SeverityBadge.Background = new SolidColorBrush(Color.FromRgb(34, 197, 94)); // SuccessGreen
            }

            audit.LogAction("ALERT_VIEWED", $"Analistul a investigat alerta: {alert.Title}");
        }

        private void TitleBar_MouseDown(object sender, System.Windows.Input.MouseButtonEventArgs e)
        {
            if (e.ChangedButton == System.Windows.Input.MouseButton.Left)
                this.DragMove();
        }

        private void Close_Click(object sender, RoutedEventArgs e) => this.Close();
    }
}