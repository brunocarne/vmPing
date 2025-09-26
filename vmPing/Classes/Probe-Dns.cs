using System;
using System.Collections.ObjectModel;
using System.Threading;

namespace vmPing.Classes
{
    public partial class Probe
    {
        private async void PerformDnsLookup(CancellationToken cancellationToken)
        {
            IsActive = true;
            History = new ObservableCollection<string>();
            Status = ProbeStatus.Scanner;

            try
            {
                var lines = await DnsLookupService.LookupAndFormatAsync(Hostname, cancellationToken);

                foreach (var line in lines)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    AddHistory(line);
                }

                AddHistory(string.Empty);
                AddHistory("\u2605 Done");
            }
            catch (OperationCanceledException)
            {
            }
            catch (Exception ex)
            {
                if (!cancellationToken.IsCancellationRequested)
                {
                    AddHistory(string.Empty);
                    AddHistory($"\u2605 DNS lookup failed: {ex.Message}");
                }
            }
            finally
            {
                IsActive = false;
            }
        }
    }
}
