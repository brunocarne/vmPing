using System;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using vmPing.Classes;

namespace vmPing.Views
{
    public partial class DnsLookupWindow : Window
    {
        private readonly MainWindow mainWindow;
        private CancellationTokenSource cancellation;
        private bool isLookupInProgress;

        public DnsLookupWindow(MainWindow owner)
        {
            InitializeComponent();
            mainWindow = owner;
            Topmost = ApplicationOptions.IsAlwaysOnTopEnabled;
        }

        private void Window_Loaded(object sender, RoutedEventArgs e)
        {
            HostnameTextBox.Focus();
            HostnameTextBox.SelectAll();
            UpdateActionButtons();
        }

        private async void LookupButton_Click(object sender, RoutedEventArgs e)
        {
            if (isLookupInProgress)
                return;

            if (string.IsNullOrWhiteSpace(HostnameTextBox.Text))
            {
                StatusText.Text = "Enter a hostname or IP address.";
                HostnameTextBox.Focus();
                return;
            }

            cancellation?.Cancel();
            cancellation = new CancellationTokenSource();
            isLookupInProgress = true;
            UpdateUiForLookup(started: true);

            try
            {
                StatusText.Text = "Resolving DNS records...";
                ResultsTextBox.Clear();
                UpdateActionButtons();

                var target = HostnameTextBox.Text.Trim();
                var lines = await DnsLookupService.LookupAndFormatAsync(target, cancellation.Token);

                ResultsTextBox.Text = string.Join(Environment.NewLine, lines);
                StatusText.Text = $"\u2605 Lookup complete ({lines.Count} lines).";
            }
            catch (OperationCanceledException)
            {
                StatusText.Text = "\u2022 Lookup cancelled.";
            }
            catch (Exception ex)
            {
                StatusText.Text = $"\u26A0 {ex.Message}";
                ResultsTextBox.Clear();
                UpdateActionButtons();
            }
            finally
            {
                isLookupInProgress = false;
                UpdateUiForLookup(started: false);
                UpdateActionButtons();
            }
        }

        private void CloseButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private void CancelButton_Click(object sender, RoutedEventArgs e)
        {
            CancelLookup();
        }

        private void CancelLookup()
        {
            if (!isLookupInProgress)
                return;

            cancellation?.Cancel();
        }

        private void CopyButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrEmpty(ResultsTextBox.Text))
                return;

            Clipboard.SetText(ResultsTextBox.Text);
            StatusText.Text = "\u2022 Results copied to clipboard.";
        }

        private void AddProbeButton_Click(object sender, RoutedEventArgs e)
        {
            if (string.IsNullOrWhiteSpace(HostnameTextBox.Text))
            {
                StatusText.Text = "Enter a hostname first.";
                HostnameTextBox.Focus();
                return;
            }

            mainWindow?.StartDnsProbe(HostnameTextBox.Text.Trim());
            StatusText.Text = "\u2022 DNS probe added to main window.";
        }

        private void HostnameTextBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                e.Handled = true;
                LookupButton_Click(sender, e);
            }
        }

        private void UpdateUiForLookup(bool started)
        {
            HostnameTextBox.IsEnabled = !started;
            LookupButton.IsEnabled = !started;
            CancelButton.Visibility = started ? Visibility.Visible : Visibility.Collapsed;
            CancelButton.IsEnabled = started;
        }

        protected override void OnClosed(EventArgs e)
        {
            cancellation?.Cancel();
            cancellation?.Dispose();
            cancellation = null;
            base.OnClosed(e);
        }

        private void UpdateActionButtons()
        {
            CopyButton.IsEnabled = !string.IsNullOrEmpty(ResultsTextBox.Text);
        }
    }
}


