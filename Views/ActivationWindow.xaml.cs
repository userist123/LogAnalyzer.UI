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
            
            // Afișăm ID-ul pe ecran
            TxtHardwareId.Text = _licenseService.GetHardwareId();
        }

        private void Activate_Click(object sender, RoutedEventArgs e)
        {
            if (_licenseService.ValidateAndSaveKey(TxtLicenseKey.Text))
            {
                MessageBox.Show("✅ Licența a fost activată cu succes! Aplicația va porni.", "Activare Reușită", MessageBoxButton.OK, MessageBoxImage.Information);
                this.DialogResult = true;
            }
            else
            {
                MessageBox.Show("❌ Cheia de licență este invalidă pentru acest Hardware ID.", "Eroare Activare", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void Exit_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }
    }
}