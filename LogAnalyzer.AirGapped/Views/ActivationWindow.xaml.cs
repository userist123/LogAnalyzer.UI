using System.Windows;
using LogAnalyzer.Core.Services;

namespace LogAnalyzer.UI.Views
{
    public partial class ActivationWindow : Window
    {
        private readonly LicenseService _licenseService;

        public ActivationWindow(LicenseService licenseService)
        {
            InitializeComponent();
            _licenseService = licenseService;
            
            TxtHardwareId.Text = _licenseService.GetHardwareId();
        }

        private void CopyHwid_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(TxtHardwareId.Text))
            {
                Clipboard.SetText(TxtHardwareId.Text);
                TxtStatus.Text = "HWID copied to clipboard.";
                TxtStatus.Foreground = Application.Current.TryFindResource("SuccessBrush") as System.Windows.Media.Brush;
            }
        }

        private void Activate_Click(object sender, RoutedEventArgs e)
        {
            if (_licenseService.ValidateAndSaveKey(TxtLicenseKey.Text))
            {
                MessageBox.Show("Platform node license verified and activated successfully.", "Activation Successful", MessageBoxButton.OK, MessageBoxImage.Information);
                this.DialogResult = true;
            }
            else
            {
                TxtStatus.Text = "Invalid license key for this Hardware ID.";
                TxtStatus.Foreground = Application.Current.TryFindResource("CriticalBrush") as System.Windows.Media.Brush;
            }
        }

        private void Exit_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }
    }
}