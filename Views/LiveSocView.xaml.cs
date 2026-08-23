using System.Windows;
using System.Windows.Controls;

namespace LogAnalyzer.UI.Views
{
    public partial class LiveSocView : UserControl
    {
        public LiveSocView()
        {
            InitializeComponent();
        }

        private void SimulateMenuButton_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.ContextMenu != null)
            {
                btn.ContextMenu.PlacementTarget = btn;
                btn.ContextMenu.IsOpen = true;
            }
        }
    }
}