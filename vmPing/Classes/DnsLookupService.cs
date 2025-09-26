using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace vmPing.Classes
{
    internal static class DnsLookupService
    {
        private const int DefaultTimeoutMilliseconds = 4000;
        private static readonly RandomNumberGenerator IdGenerator = RandomNumberGenerator.Create();

        private static readonly IReadOnlyList<DnsResolver> PublicResolvers = new[]
        {
            new DnsResolver("Cloudflare", IPAddress.Parse("1.1.1.1")),
            new DnsResolver("Google", IPAddress.Parse("8.8.8.8")),
            new DnsResolver("Quad9", IPAddress.Parse("9.9.9.9"))
        };

        internal static async Task<IReadOnlyList<string>> LookupAndFormatAsync(string input, CancellationToken token)
        {
            var payload = await LookupAsync(input, token).ConfigureAwait(false);
            return BuildHistoryLines(payload);
        }

        private static async Task<DnsLookupPayload> LookupAsync(string input, CancellationToken token)
        {
            if (string.IsNullOrWhiteSpace(input))
                throw new ArgumentException("Hostname cannot be empty.", nameof(input));

            token.ThrowIfCancellationRequested();

            var trimmedInput = input.Trim();
            var isIp = IPAddress.TryParse(trimmedInput, out var parsedIp);
            var queryName = isIp ? BuildReverseLookupName(parsedIp) : trimmedInput.TrimEnd('.');

            var recordTypes = isIp
                ? new[] { DnsRecordType.Ptr, DnsRecordType.Soa }
                : new[] { DnsRecordType.A, DnsRecordType.Aaaa, DnsRecordType.CName, DnsRecordType.Mx, DnsRecordType.Txt, DnsRecordType.Ns, DnsRecordType.Soa };

            var resolvers = GetResolvers().ToList();
            if (resolvers.Count == 0)
                resolvers.AddRange(PublicResolvers);

            var reports = new List<DnsLookupReport>();
            foreach (var resolver in resolvers)
            {
                token.ThrowIfCancellationRequested();
                reports.Add(await QueryResolverAsync(trimmedInput, queryName, resolver, recordTypes, token).ConfigureAwait(false));
            }

            return new DnsLookupPayload(trimmedInput, queryName, isIp, recordTypes, reports);
        }
        private static IEnumerable<DnsResolver> GetResolvers()
        {
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var resolver in GetLocalResolvers())
            {
                if (seen.Add(resolver.Address.ToString()))
                    yield return resolver;
            }

            foreach (var resolver in PublicResolvers)
            {
                if (seen.Add(resolver.Address.ToString()))
                    yield return resolver;
            }
        }

        private static IEnumerable<DnsResolver> GetLocalResolvers()
        {
            var resolvers = new List<DnsResolver>();

            try
            {
                foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
                {
                    if (adapter.OperationalStatus != OperationalStatus.Up)
                        continue;

                    IPInterfaceProperties properties;
                    try
                    {
                        properties = adapter.GetIPProperties();
                    }
                    catch (NetworkInformationException)
                    {
                        continue;
                    }

                    foreach (var address in properties.DnsAddresses)
                    {
                        if (address == null || address.Equals(IPAddress.Any) || address.Equals(IPAddress.IPv6Any))
                            continue;

                        resolvers.Add(new DnsResolver(adapter.Name, address));
                    }
                }
            }
            catch (NetworkInformationException)
            {
                // Ignore interface enumeration errors and fall back to public resolvers.
            }

            return resolvers;
        }
        private static async Task<DnsLookupReport> QueryResolverAsync(string originalInput, string queryName, DnsResolver resolver, IReadOnlyList<DnsRecordType> recordTypes, CancellationToken token)
        {
            var report = new DnsLookupReport(resolver);

            foreach (var recordType in recordTypes)
            {
                token.ThrowIfCancellationRequested();

                try
                {
                    var response = await QueryRecordAsync(queryName, recordType, resolver.Address, token).ConfigureAwait(false);

                    if (response.ResponseCode == DnsResponseCode.NxDomain)
                    {
                        if (response.Authority.Count > 0)
                            report.Authority.AddRange(response.Authority);

                        report.Error = "NXDOMAIN (name does not exist).";
                        break;
                    }

                    if (response.ResponseCode != DnsResponseCode.NoError)
                    {
                        if (response.Authority.Count > 0)
                            report.Authority.AddRange(response.Authority);

                        report.Error = $"Server returned {response.ResponseCode}.";
                        break;
                    }

                    if (response.Answers.TryGetValue(recordType, out var answers))
                    {
                        var unique = answers
                            .GroupBy(entry => entry.ComparisonValue, StringComparer.OrdinalIgnoreCase)
                            .Select(group => group.First())
                            .OrderBy(entry => entry.ComparisonValue, StringComparer.OrdinalIgnoreCase)
                            .ToList();

                        report.Records[recordType] = unique;
                    }
                    else
                    {
                        report.Records[recordType] = new List<DnsRecordEntry>();
                    }

                    if (response.Authority.Count > 0)
                        report.Authority.AddRange(response.Authority);

                    if (response.Additional.Count > 0)
                        report.Additional.AddRange(response.Additional);

                    if (response.IsTruncated)
                        report.Notes.Add($"Response for {GetRecordTypeLabel(recordType)} truncated; results may be incomplete.");
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (TimeoutException)
                {
                    report.Error = $"Timed out after {DefaultTimeoutMilliseconds} ms.";
                    break;
                }
                catch (SocketException ex)
                {
                    report.Error = $"Socket error: {ex.Message}";
                    break;
                }
                catch (Exception ex)
                {
                    report.RecordErrors[recordType] = ex.Message;
                }
            }

            if (report.Authority.Count > 1)
                Deduplicate(report.Authority);
            if (report.Additional.Count > 1)
                Deduplicate(report.Additional);

            return report;
        }
        private static async Task<DnsQueryResponse> QueryRecordAsync(string queryName, DnsRecordType recordType, IPAddress resolverAddress, CancellationToken token)
        {
            var id = GenerateMessageId();
            var payload = BuildQuery(queryName, recordType, id);
            var endpoint = new IPEndPoint(resolverAddress, 53);

            using (var client = new UdpClient(resolverAddress.AddressFamily))
            {
                client.Client.SendTimeout = DefaultTimeoutMilliseconds;
                client.Client.ReceiveTimeout = DefaultTimeoutMilliseconds;

                await client.SendAsync(payload, payload.Length, endpoint).ConfigureAwait(false);

                var receiveTask = client.ReceiveAsync();
                var timeoutTask = Task.Delay(DefaultTimeoutMilliseconds, token);
                var completed = await Task.WhenAny(receiveTask, timeoutTask).ConfigureAwait(false);

                if (completed != receiveTask)
                    throw new TimeoutException();

                var result = await receiveTask.ConfigureAwait(false);
                return ParseResponse(result.Buffer);
            }
        }

        private static DnsQueryResponse ParseResponse(byte[] buffer)
        {
            if (buffer == null || buffer.Length < 12)
                throw new InvalidDataException("Invalid DNS response.");

            var response = new DnsQueryResponse();
            int offset = 0;

            ushort id = ReadUInt16(buffer, ref offset);
            ushort flags = ReadUInt16(buffer, ref offset);
            ushort questionCount = ReadUInt16(buffer, ref offset);
            ushort answerCount = ReadUInt16(buffer, ref offset);
            ushort authorityCount = ReadUInt16(buffer, ref offset);
            ushort additionalCount = ReadUInt16(buffer, ref offset);

            response.ResponseCode = (DnsResponseCode)(flags & 0x000F);
            response.IsTruncated = (flags & 0x0200) != 0;

            for (int i = 0; i < questionCount; i++)
            {
                SkipQuestion(buffer, ref offset);
            }

            for (int i = 0; i < answerCount; i++)
            {
                var record = ParseRecord(buffer, ref offset);
                AddRecord(response.Answers, record);
            }

            for (int i = 0; i < authorityCount; i++)
            {
                response.Authority.Add(ParseRecord(buffer, ref offset));
            }

            for (int i = 0; i < additionalCount; i++)
            {
                response.Additional.Add(ParseRecord(buffer, ref offset));
            }

            return response;
        }

        private static void SkipQuestion(byte[] buffer, ref int offset)
        {
            ReadDomainName(buffer, ref offset);
            if (offset + 4 > buffer.Length)
                throw new InvalidDataException("Unexpected end of DNS question.");
            offset += 4;
        }

        private static void AddRecord(Dictionary<DnsRecordType, List<DnsRecordEntry>> store, DnsRecordEntry record)
        {
            if (!store.TryGetValue(record.Type, out var list))
            {
                list = new List<DnsRecordEntry>();
                store[record.Type] = list;
            }

            list.Add(record);
        }

        private static DnsRecordEntry ParseRecord(byte[] buffer, ref int offset)
        {
            var name = ReadDomainName(buffer, ref offset);
            var typeValue = ReadUInt16(buffer, ref offset);
            var dataClass = ReadUInt16(buffer, ref offset);
            var ttl = ReadUInt32(buffer, ref offset);
            var dataLength = ReadUInt16(buffer, ref offset);

            if (offset + dataLength > buffer.Length)
                throw new InvalidDataException("DNS record length exceeds buffer.");

            var recordType = (DnsRecordType)typeValue;

            var entry = ParseRecordValue(name, recordType, dataClass, ttl, buffer, offset, dataLength);
            offset += dataLength;
            return entry;
        }

        private static DnsRecordEntry ParseRecordValue(string owner, DnsRecordType recordType, ushort dataClass, uint ttl, byte[] buffer, int dataOffset, int dataLength)
        {
            switch (recordType)
            {
                case DnsRecordType.A:
                    if (dataLength != 4)
                        throw new InvalidDataException("Invalid A record length.");
                    var addressBytes = new byte[4];
                    Buffer.BlockCopy(buffer, dataOffset, addressBytes, 0, 4);
                    var ipv4 = new IPAddress(addressBytes);
                    return new DnsRecordEntry(owner, recordType, dataClass, ttl, $"{FormatOwner(owner)} -> {ipv4}", ipv4.ToString());

                case DnsRecordType.Aaaa:
                    if (dataLength != 16)
                        throw new InvalidDataException("Invalid AAAA record length.");
                    var ipv6Bytes = new byte[16];
                    Buffer.BlockCopy(buffer, dataOffset, ipv6Bytes, 0, 16);
                    var ipv6 = new IPAddress(ipv6Bytes);
                    return new DnsRecordEntry(owner, recordType, dataClass, ttl, $"{FormatOwner(owner)} -> {ipv6}", ipv6.ToString());

                case DnsRecordType.CName:
                case DnsRecordType.Ns:
                case DnsRecordType.Ptr:
                    {
                        int pointer = dataOffset;
                        var target = ReadDomainName(buffer, ref pointer);
                        var formatted = FormatDomain(target);
                        return new DnsRecordEntry(owner, recordType, dataClass, ttl, $"{FormatOwner(owner)} -> {formatted}", NormalizeDomain(target));
                    }

                case DnsRecordType.Mx:
                    {
                        int pointer = dataOffset;
                        var preference = ReadUInt16(buffer, ref pointer);
                        var target = ReadDomainName(buffer, ref pointer);
                        var formatted = FormatDomain(target);
                        var value = $"{FormatOwner(owner)} -> {preference} {formatted}";
                        var comparison = $"{preference} {NormalizeDomain(target)}";
                        return new DnsRecordEntry(owner, recordType, dataClass, ttl, value, comparison);
                    }

                case DnsRecordType.Txt:
                    {
                        int position = dataOffset;
                        int end = dataOffset + dataLength;
                        var segments = new List<string>();

                        while (position < end)
                        {
                            byte segmentLength = buffer[position++];
                            if (position + segmentLength > end)
                                throw new InvalidDataException("Invalid TXT record segment.");

                            var segment = Encoding.UTF8.GetString(buffer, position, segmentLength);
                            segments.Add(segment);
                            position += segmentLength;
                        }

                        var quoted = string.Join("\" \"", segments.Select(EscapeQuotes));
                        var display = $"{FormatOwner(owner)} -> \"{quoted}\"";
                        var comparison = string.Join("|", segments);
                        return new DnsRecordEntry(owner, recordType, dataClass, ttl, display, comparison);
                    }

                case DnsRecordType.Soa:
                    {
                        int pointer = dataOffset;
                        var primary = ReadDomainName(buffer, ref pointer);
                        var responsible = ReadDomainName(buffer, ref pointer);
                        var serial = ReadUInt32(buffer, ref pointer);
                        var refresh = ReadUInt32(buffer, ref pointer);
                        var retry = ReadUInt32(buffer, ref pointer);
                        var expire = ReadUInt32(buffer, ref pointer);
                        var minimum = ReadUInt32(buffer, ref pointer);

                        var display = $"{FormatOwner(owner)} -> Primary:{FormatDomain(primary)} Responsible:{FormatDomain(responsible)} Serial:{serial} Refresh:{refresh} Retry:{retry} Expire:{expire} MinTTL:{minimum}";
                        var comparison = $"{NormalizeDomain(primary)}|{NormalizeDomain(responsible)}|{serial}|{refresh}|{retry}|{expire}|{minimum}";
                        return new DnsRecordEntry(owner, recordType, dataClass, ttl, display, comparison);
                    }

                default:
                    {
                        var raw = new byte[dataLength];
                        Buffer.BlockCopy(buffer, dataOffset, raw, 0, dataLength);
                        var hex = BitConverter.ToString(raw).Replace("-", string.Empty);
                        var display = $"{FormatOwner(owner)} -> \\# {dataLength} {hex}";
                        return new DnsRecordEntry(owner, recordType, dataClass, ttl, display, hex);
                    }
            }
        }
        private static IReadOnlyList<string> BuildHistoryLines(DnsLookupPayload payload)
        {
            var lines = new List<string>
            {
                $"[?] DNS lookup for {payload.Input}"
            };

            if (payload.IsReverseLookup)
            {
                lines.Add($"    Reverse lookup query: {payload.QueryName}");
            }
            else if (!payload.Input.Equals(payload.QueryName, StringComparison.OrdinalIgnoreCase))
            {
                lines.Add($"    Query name: {payload.QueryName}");
            }

            var summaryLines = BuildPropagationSummary(payload).ToList();
            if (summaryLines.Count > 0)
            {
                lines.Add(string.Empty);
                lines.Add("Propagation summary:");
                foreach (var summary in summaryLines)
                    lines.Add($"  {summary}");
            }

            foreach (var report in payload.Reports)
            {
                lines.Add(string.Empty);
                lines.Add($"Resolver: {report.Resolver.DisplayName}");

                if (!string.IsNullOrEmpty(report.Error))
                {
                    lines.Add($"  Error: {report.Error}");
                    if (report.Authority.Count > 0)
                    {
                        lines.Add("  Authority:");
                        foreach (var record in report.Authority)
                            lines.Add($"    {record.ToHistoryString()}");
                    }

                    continue;
                }

                foreach (var type in payload.RecordTypes)
                {
                    var label = GetRecordTypeLabel(type);
                    if (!report.Records.TryGetValue(type, out var records) || records.Count == 0)
                    {
                        if (report.RecordErrors.TryGetValue(type, out var errorMessage))
                            lines.Add($"  {label}: {errorMessage}");
                        else
                            lines.Add($"  {label}: (no records)");
                        continue;
                    }

                    lines.Add($"  {label}:");
                    foreach (var record in records)
                        lines.Add($"    {record.ToHistoryString()}");

                    if (report.RecordErrors.TryGetValue(type, out var warning))
                        lines.Add($"    Note: {warning}");
                }

                if (report.Authority.Count > 0)
                {
                    lines.Add("  Authority:");
                    foreach (var record in report.Authority)
                        lines.Add($"    {record.ToHistoryString()}");
                }

                if (report.Additional.Count > 0)
                {
                    lines.Add("  Additional:");
                    foreach (var record in report.Additional)
                        lines.Add($"    {record.ToHistoryString()}");
                }

                foreach (var note in report.Notes)
                    lines.Add($"  Note: {note}");
            }

            if (lines.Count > 0 && string.IsNullOrWhiteSpace(lines[lines.Count - 1]))
                lines.RemoveAt(lines.Count - 1);

            return lines;
        }

        private static IEnumerable<string> BuildPropagationSummary(DnsLookupPayload payload)
        {
            var activeReports = payload.Reports.Where(report => string.IsNullOrEmpty(report.Error)).ToList();
            if (activeReports.Count <= 1)
                yield break;

            foreach (var type in payload.RecordTypes)
            {
                var resolverValues = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);

                foreach (var report in activeReports)
                {
                    if (!report.Records.TryGetValue(type, out var records) || records.Count == 0)
                    {
                        resolverValues[report.Resolver.DisplayName] = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        continue;
                    }

                    resolverValues[report.Resolver.DisplayName] = new HashSet<string>(
                        records.Select(record => record.ComparisonValue),
                        StringComparer.OrdinalIgnoreCase);
                }

                var normalized = resolverValues.Values
                    .Select(set => string.Join("|", set.OrderBy(value => value, StringComparer.OrdinalIgnoreCase)))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .ToList();

                var label = GetRecordTypeLabel(type);

                if (normalized.Count == 1)
                {
                    if (resolverValues.Values.All(set => set.Count == 0))
                        yield return $"{label}: no records reported yet.";
                    else
                        yield return $"{label}: consistent across {resolverValues.Count} resolvers.";
                }
                else
                {
                    var missing = resolverValues.Where(pair => pair.Value.Count == 0).Select(pair => pair.Key).ToList();
                    if (missing.Count > 0)
                        yield return $"{label}: inconsistent, missing on {string.Join(", ", missing)}.";
                    else
                        yield return $"{label}: inconsistent values across resolvers.";
                }
            }
        }
        private static ushort GenerateMessageId()
        {
            var buffer = new byte[2];
            IdGenerator.GetBytes(buffer);
            return (ushort)((buffer[0] << 8) | buffer[1]);
        }

        private static byte[] BuildQuery(string queryName, DnsRecordType recordType, ushort id)
        {
            using (var stream = new MemoryStream())
            using (var writer = new BinaryWriter(stream))
            {
                WriteUInt16(writer, id);
                WriteUInt16(writer, 0x0100);
                WriteUInt16(writer, 1);
                WriteUInt16(writer, 0);
                WriteUInt16(writer, 0);
                WriteUInt16(writer, 0);

                WriteQuestion(writer, queryName);
                WriteUInt16(writer, (ushort)recordType);
                WriteUInt16(writer, 1);

                return stream.ToArray();
            }
        }

        private static void WriteQuestion(BinaryWriter writer, string queryName)
        {
            if (string.IsNullOrWhiteSpace(queryName) || queryName == ".")
            {
                writer.Write((byte)0);
            }
            else
            {
                var labels = queryName.Trim('.').Split('.');
                foreach (var label in labels)
                {
                    var bytes = Encoding.ASCII.GetBytes(label);
                    if (bytes.Length > 63)
                        throw new InvalidOperationException("DNS label exceeds 63 characters.");
                    writer.Write((byte)bytes.Length);
                    writer.Write(bytes);
                }

                writer.Write((byte)0);
            }
        }

        private static void WriteUInt16(BinaryWriter writer, ushort value)
        {
            writer.Write((byte)(value >> 8));
            writer.Write((byte)(value & 0xFF));
        }

        private static string ReadDomainName(byte[] buffer, ref int offset)
        {
            var labels = new List<string>();
            int originalOffset = offset;
            bool jumped = false;
            int safety = 0;

            while (true)
            {
                if (offset >= buffer.Length)
                    throw new InvalidDataException("Unexpected end of DNS response while reading name.");

                byte length = buffer[offset++];
                if (length == 0)
                    break;

                if ((length & 0xC0) == 0xC0)
                {
                    if (offset >= buffer.Length)
                        throw new InvalidDataException("Invalid DNS compression pointer.");

                    int pointer = ((length & 0x3F) << 8) | buffer[offset++];
                    if (pointer >= buffer.Length)
                        throw new InvalidDataException("Invalid DNS compression pointer.");

                    if (!jumped)
                    {
                        originalOffset = offset;
                        jumped = true;
                    }

                    offset = pointer;

                    if (++safety > buffer.Length)
                        throw new InvalidDataException("DNS compression pointer loop detected.");

                    continue;
                }

                if (offset + length > buffer.Length)
                    throw new InvalidDataException("Invalid DNS label length.");

                var label = Encoding.ASCII.GetString(buffer, offset, length);
                labels.Add(label);
                offset += length;

                if (++safety > buffer.Length)
                    throw new InvalidDataException("DNS label parsing exceeded buffer size.");
            }

            if (jumped)
                offset = originalOffset;

            return labels.Count == 0 ? "." : string.Join(".", labels);
        }

        private static ushort ReadUInt16(byte[] buffer, ref int offset)
        {
            if (offset + 2 > buffer.Length)
                throw new InvalidDataException("Unexpected end of DNS response.");

            ushort value = (ushort)((buffer[offset] << 8) | buffer[offset + 1]);
            offset += 2;
            return value;
        }

        private static uint ReadUInt32(byte[] buffer, ref int offset)
        {
            if (offset + 4 > buffer.Length)
                throw new InvalidDataException("Unexpected end of DNS response.");

            uint value = (uint)(
                (buffer[offset] << 24) |
                (buffer[offset + 1] << 16) |
                (buffer[offset + 2] << 8) |
                buffer[offset + 3]);

            offset += 4;
            return value;
        }

        private static string EscapeQuotes(string value)
        {
            return value?.Replace("\"", "\\\"") ?? string.Empty;
        }

        private static string FormatDomain(string domain)
        {
            if (string.IsNullOrEmpty(domain) || domain == ".")
                return ".";
            var trimmed = domain.TrimEnd('.');
            return $"{trimmed}.";
        }

        private static string FormatOwner(string owner)
        {
            if (string.IsNullOrEmpty(owner) || owner == ".")
                return ".";
            return FormatDomain(owner);
        }

        private static string NormalizeDomain(string domain)
        {
            if (string.IsNullOrEmpty(domain) || domain == ".")
                return ".";
            return domain.TrimEnd('.').ToLowerInvariant();
        }

        private static void Deduplicate(List<DnsRecordEntry> records)
        {
            if (records == null || records.Count <= 1)
                return;

            var unique = records
                .GroupBy(record => $"{NormalizeDomain(record.Owner)}|{record.Type}|{record.ComparisonValue}", StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .OrderBy(record => NormalizeDomain(record.Owner), StringComparer.OrdinalIgnoreCase)
                .ThenBy(record => record.ComparisonValue, StringComparer.OrdinalIgnoreCase)
                .ToList();

            records.Clear();
            records.AddRange(unique);
        }

        private static string GetRecordTypeLabel(DnsRecordType recordType)
        {
            switch (recordType)
            {
                case DnsRecordType.A:
                    return "A";
                case DnsRecordType.Aaaa:
                    return "AAAA";
                case DnsRecordType.CName:
                    return "CNAME";
                case DnsRecordType.Mx:
                    return "MX";
                case DnsRecordType.Txt:
                    return "TXT";
                case DnsRecordType.Ns:
                    return "NS";
                case DnsRecordType.Ptr:
                    return "PTR";
                case DnsRecordType.Soa:
                    return "SOA";
                default:
                    return recordType.ToString().ToUpperInvariant();
            }
        }

        private static string BuildReverseLookupName(IPAddress address)
        {
            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                return string.Join(".", address.GetAddressBytes().Reverse()) + ".in-addr.arpa";
            }

            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                var bytes = address.GetAddressBytes();
                var hex = new StringBuilder(bytes.Length * 2);
                foreach (var b in bytes)
                    hex.Append(b.ToString("x2"));

                var characters = hex.ToString().ToCharArray();
                Array.Reverse(characters);
                return string.Join(".", characters) + ".ip6.arpa";
            }

            throw new NotSupportedException("Unsupported address family for reverse lookup.");
        }

        private sealed class DnsLookupPayload
        {
            public DnsLookupPayload(string input, string queryName, bool isReverseLookup, IReadOnlyList<DnsRecordType> recordTypes, IReadOnlyList<DnsLookupReport> reports)
            {
                Input = input;
                QueryName = queryName;
                IsReverseLookup = isReverseLookup;
                RecordTypes = recordTypes;
                Reports = reports;
            }

            public string Input { get; }
            public string QueryName { get; }
            public bool IsReverseLookup { get; }
            public IReadOnlyList<DnsRecordType> RecordTypes { get; }
            public IReadOnlyList<DnsLookupReport> Reports { get; }
        }

        private sealed class DnsLookupReport
        {
            public DnsLookupReport(DnsResolver resolver)
            {
                Resolver = resolver;
                Records = new Dictionary<DnsRecordType, List<DnsRecordEntry>>();
                RecordErrors = new Dictionary<DnsRecordType, string>();
                Authority = new List<DnsRecordEntry>();
                Additional = new List<DnsRecordEntry>();
                Notes = new List<string>();
            }

            public DnsResolver Resolver { get; }
            public Dictionary<DnsRecordType, List<DnsRecordEntry>> Records { get; }
            public Dictionary<DnsRecordType, string> RecordErrors { get; }
            public List<DnsRecordEntry> Authority { get; }
            public List<DnsRecordEntry> Additional { get; }
            public List<string> Notes { get; }
            public string Error { get; set; }
        }

        private sealed class DnsResolver
        {
            public DnsResolver(string name, IPAddress address)
            {
                Name = string.IsNullOrWhiteSpace(name) ? address.ToString() : name;
                Address = address;
            }

            public string Name { get; }
            public IPAddress Address { get; }
            public string DisplayName => $"{Name} ({Address})";
        }

        private sealed class DnsQueryResponse
        {
            public DnsQueryResponse()
            {
                Answers = new Dictionary<DnsRecordType, List<DnsRecordEntry>>();
                Authority = new List<DnsRecordEntry>();
                Additional = new List<DnsRecordEntry>();
            }

            public Dictionary<DnsRecordType, List<DnsRecordEntry>> Answers { get; }
            public List<DnsRecordEntry> Authority { get; }
            public List<DnsRecordEntry> Additional { get; }
            public DnsResponseCode ResponseCode { get; set; }
            public bool IsTruncated { get; set; }
        }

        private sealed class DnsRecordEntry
        {
            public DnsRecordEntry(string owner, DnsRecordType type, ushort dataClass, uint ttl, string value, string comparisonValue)
            {
                Owner = owner;
                Type = type;
                Class = dataClass;
                Ttl = ttl;
                Value = value;
                ComparisonValue = comparisonValue;
            }

            public string Owner { get; }
            public DnsRecordType Type { get; }
            public ushort Class { get; }
            public uint Ttl { get; }
            public string Value { get; }
            public string ComparisonValue { get; }

            public string ToHistoryString()
            {
                return $"{Value} (TTL {Ttl})";
            }
        }

        private enum DnsResponseCode
        {
            NoError = 0,
            FormatError = 1,
            ServerFailure = 2,
            NxDomain = 3,
            NotImplemented = 4,
            Refused = 5,
            YxDomain = 6,
            YxRrSet = 7,
            NxRrSet = 8,
            NotAuthoritative = 9,
            NotZone = 10
        }

        private enum DnsRecordType : ushort
        {
            A = 1,
            Ns = 2,
            CName = 5,
            Soa = 6,
            Ptr = 12,
            Mx = 15,
            Txt = 16,
            Aaaa = 28,
            Caa = 257
        }
    }
}
