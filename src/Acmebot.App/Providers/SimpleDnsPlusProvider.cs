using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json.Serialization;

using Acmebot.App.Options;

namespace Acmebot.App.Providers;

public class SimpleDnsPlusProvider(SimpleDnsPlusOptions options) : IDnsProvider
{
    private readonly SimpleDnsPlusClient _client = new(options.RootApiUrl, options.ApiKeyUser, options.SecretKey);

    public string Name => "SimpleDNS Plus";

    public TimeSpan PropagationDelay => TimeSpan.FromSeconds(10);

    public async Task<IReadOnlyList<DnsZone>> ListZonesAsync(CancellationToken cancellationToken = default)
    {
        var zones = await _client.ListZonesAsync(cancellationToken);

        return zones.Select(x => new DnsZone(this) { Id = x.Name, Name = x.Name }).ToArray();
    }

    public async Task CreateTxtRecordAsync(DnsZone zone, string relativeRecordName, string[] values, CancellationToken cancellationToken = default)
    {
        var recordName = DnsRecordName.ToFqdn(zone.Name, relativeRecordName);

        foreach (var value in values)
        {
            await _client.PatchRecordAsync(zone.Id, new DnsEntry
            {
                Name = recordName,
                Type = "TXT",
                Ttl = 60,
                Data = value,
                Remove = false
            }, cancellationToken);
        }
    }

    public async Task DeleteTxtRecordAsync(DnsZone zone, string relativeRecordName, CancellationToken cancellationToken = default)
    {
        var recordName = DnsRecordName.ToFqdn(zone.Name, relativeRecordName);

        var records = await _client.ListRecordsAsync(zone.Id, cancellationToken);

        var recordsToDelete = records.Where(x => string.Equals(x.Name?.TrimEnd('.'), recordName, StringComparison.OrdinalIgnoreCase) && x.Type == "TXT");

        foreach (var record in recordsToDelete)
        {
            record.Remove = true;

            await _client.PatchRecordAsync(zone.Id, record, cancellationToken);
        }
    }

    private class SimpleDnsPlusClient
    {
        public SimpleDnsPlusClient(Uri rootApiUrl, string apiKeyUser, string secretKey)
        {
            // The base address needs a trailing slash so relative paths append to it.
            var baseAddress = rootApiUrl.AbsoluteUri.EndsWith('/') ? rootApiUrl : new Uri(rootApiUrl.AbsoluteUri + "/");

            _httpClient = DnsProviderHttpClient.Create(baseAddress);
            _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Convert.ToBase64String(Encoding.ASCII.GetBytes($"{apiKeyUser}:{secretKey}")));
        }

        private readonly HttpClient _httpClient;

        public async Task<IReadOnlyList<Domain>> ListZonesAsync(CancellationToken cancellationToken = default)
        {
            var domains = await _httpClient.GetFromJsonAsync<Domain[]>("zones", cancellationToken);

            return domains ?? [];
        }

        public async Task<IReadOnlyList<DnsEntry>> ListRecordsAsync(string zoneId, CancellationToken cancellationToken = default)
        {
            var entries = await _httpClient.GetFromJsonAsync<DnsEntry[]>($"zones/{Uri.EscapeDataString(zoneId)}/records", cancellationToken);

            return entries ?? [];
        }

        // Records are added or removed by PATCHing a list of entries; Remove selects the operation.
        public async Task PatchRecordAsync(string zoneId, DnsEntry entry, CancellationToken cancellationToken = default)
        {
            using var request = new HttpRequestMessage(HttpMethod.Patch, $"zones/{Uri.EscapeDataString(zoneId)}/records")
            {
                Content = JsonContent.Create(new[] { entry })
            };

            var response = await _httpClient.SendAsync(request, cancellationToken);

            response.EnsureSuccessStatusCode();
        }
    }

    internal class Domain
    {
        [JsonPropertyName("Name")]
        public required string Name { get; set; }

        [JsonPropertyName("Type")]
        public string? Type { get; set; }
    }

    internal class DnsEntry
    {
        [JsonPropertyName("Name")]
        public string? Name { get; set; }

        [JsonPropertyName("TTL")]
        public int Ttl { get; set; }

        [JsonPropertyName("Type")]
        public string? Type { get; set; }

        [JsonPropertyName("Data")]
        public string? Data { get; set; }

        [JsonPropertyName("Remove")]
        public bool Remove { get; set; }
    }
}
