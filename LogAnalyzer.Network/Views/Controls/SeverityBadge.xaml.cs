using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;

namespace LogAnalyzer.UI.Views.Controls
{
    public partial class SeverityBadge : UserControl
    {
        public static readonly DependencyProperty SeverityProperty =
            DependencyProperty.Register(nameof(Severity), typeof(string), typeof(SeverityBadge),
                new PropertyMetadata("INFO", OnSeverityChanged));

        public string Severity
        {
            get => (string)GetValue(SeverityProperty);
            set => SetValue(SeverityProperty, value);
        }

        public SeverityBadge()
        {
            InitializeComponent();
            UpdateBadge(Severity);
        }

        private static void OnSeverityChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
        {
            if (d is SeverityBadge badge)
            {
                badge.UpdateBadge(e.NewValue as string);
            }
        }

        private void UpdateBadge(string? severity)
        {
            var s = (severity ?? "INFO").ToUpperInvariant();
            BadgeText.Text = s;
            if (s.Contains("CRIT"))
            {
                BadgeBorder.Background = new SolidColorBrush(Color.FromRgb(0x2D, 0x12, 0x17));
                BadgeBorder.BorderBrush = Application.Current.TryFindResource("CriticalBrush") as Brush;
                BadgeText.Foreground = Application.Current.TryFindResource("CriticalBrush") as Brush;
            }
            else if (s.Contains("HIGH") || s.Contains("AVERT"))
            {
                BadgeBorder.Background = new SolidColorBrush(Color.FromRgb(0x2D, 0x1E, 0x12));
                BadgeBorder.BorderBrush = Application.Current.TryFindResource("HighBrush") as Brush;
                BadgeText.Foreground = Application.Current.TryFindResource("HighBrush") as Brush;
            }
            else if (s.Contains("MED"))
            {
                BadgeBorder.Background = new SolidColorBrush(Color.FromRgb(0x2B, 0x24, 0x10));
                BadgeBorder.BorderBrush = Application.Current.TryFindResource("MediumBrush") as Brush;
                BadgeText.Foreground = Application.Current.TryFindResource("MediumBrush") as Brush;
            }
            else
            {
                BadgeBorder.Background = new SolidColorBrush(Color.FromRgb(0x15, 0x1E, 0x2E));
                BadgeBorder.BorderBrush = Application.Current.TryFindResource("PrimaryAccentBrush") as Brush;
                BadgeText.Foreground = Application.Current.TryFindResource("PrimaryAccentBrush") as Brush;
            }
        }
    }
}