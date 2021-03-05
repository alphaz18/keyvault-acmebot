using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

using KeyVault.Acmebot.Options;

using Newtonsoft.Json;

namespace KeyVault.Acmebot.Providers
{
    public class SimpleDNSPlusProvider : IDnsProvider
    {
        public SimpleDNSPlusProvider(SimpleDNSPlusOptions options)
        {
            _client = new SimpleDNSPlusClient(options.RootApiUrl, options.ApiKeyUser, options.SecretKey);
        }

        private readonly SimpleDNSPlusClient _client;

        public int PropagationSeconds => 10;

        public async Task<IReadOnlyList<DnsZone>> ListZonesAsync()
        {
            var zones = await _client.ListZonesAsync();

            return zones.Select(x => new DnsZone { Id = x.Name, Name = x.Name }).ToArray();
        }

        public async Task CreateTxtRecordAsync(DnsZone zone, string relativeRecordName, IEnumerable<string> values)
        {
            foreach (var value in values)
            {
                await _client.AddRecordAsync(zone.Id, new DnsEntry
                {
                    Name = relativeRecordName,
                    Type = "TXT",
                    Expire = 60,
                    Content = value,
                    Remove = "false"
                });
            }
        }

        public async Task DeleteTxtRecordAsync(DnsZone zone, string relativeRecordName)
        {
            var records = await _client.ListRecordsAsync(zone.Id);

            var recordsToDelete = records.Where(r => r.Name == relativeRecordName && r.Type == "TXT");

            foreach (var record in recordsToDelete)
            {
                record.Remove = "true";
                await _client.DeleteRecordAsync(zone.Id, record);
            }
        }

        private class SimpleDNSPlusClient
        {
            public SimpleDNSPlusClient(string rootApiUrl, string apiKeyUser, string secretKey)
            {
                _httpClient = new HttpClient(new ApiKeyHandler(apiKeyUser, secretKey, new HttpClientHandler()))
                {
                    BaseAddress = new Uri(rootApiUrl)
                };

                _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            }

            private readonly HttpClient _httpClient;

            public async Task<IReadOnlyList<Domain>> ListZonesAsync()
            {
                var response = await _httpClient.GetAsync("zones");

                response.EnsureSuccessStatusCode();

                var jsonDomains = await response.Content.ReadAsStringAsync();
                var domains = JsonConvert.DeserializeObject<IReadOnlyList<Domain>>(jsonDomains);
                return domains;
            }

            public async Task<IReadOnlyList<DnsEntry>> ListRecordsAsync(string zoneId)
            {
                var response = await _httpClient.GetAsync($"zones/{zoneId}/records");

                response.EnsureSuccessStatusCode();

                var jsonEntries = await response.Content.ReadAsStringAsync();
                var entries = JsonConvert.DeserializeObject<IReadOnlyList<DnsEntry>>(jsonEntries);

                return entries;
            }

            public async Task DeleteRecordAsync(string zoneId, DnsEntry entry)
            {
                List<DnsEntry> entriesToDel = new List<DnsEntry>();
                entriesToDel.Add(entry);
                var response = await _httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Patch, $"zones/{zoneId}/records")
                {
                    Content = new StringContent(JsonConvert.SerializeObject(entriesToDel), Encoding.UTF8, "application/json")
                });

                response.EnsureSuccessStatusCode();
            }

            public async Task AddRecordAsync(string zoneId, DnsEntry entry)
            {
                List<DnsEntry> entriesToAdd = new List<DnsEntry>();
                entriesToAdd.Add(entry);
                var test = JsonConvert.SerializeObject(entriesToAdd);
                var response = await _httpClient.SendAsync(new HttpRequestMessage(HttpMethod.Patch, $"zones/{zoneId}/records")
                {
                    Content = new StringContent(JsonConvert.SerializeObject(entriesToAdd).ToString(), Encoding.UTF8, "application/json")
                });

                response.EnsureSuccessStatusCode();
            }

            private sealed class ApiKeyHandler : DelegatingHandler
            {
                private string ApiKey { get; }
                private string Secret { get; }
                public ApiKeyHandler(string apiKey, string secretKey, HttpMessageHandler innerHandler) : base(innerHandler)
                {
                    if (apiKey is null)
                    {
                        throw new ArgumentNullException(nameof(apiKey));
                    }

                    if (secretKey is null)
                    {
                        throw new ArgumentNullException(nameof(secretKey));
                    }

                    if (innerHandler is null)
                    {
                        throw new ArgumentNullException(nameof(innerHandler));
                    }

                    if (string.IsNullOrWhiteSpace(apiKey))
                    {
                        throw new ArgumentException("API Key must be specified", nameof(apiKey));
                    }

                    if (string.IsNullOrWhiteSpace(secretKey))
                    {
                        throw new ArgumentException("Secret Key must be specified", nameof(secretKey));
                    }

                    ApiKey = apiKey;
                    Secret = secretKey;
                }

                protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
                {

                    request.Headers.Add("Authorization", "Basic " + Convert.ToBase64String(System.Text.ASCIIEncoding.ASCII.GetBytes(string.Format("{0}:{1}", ApiKey, Secret))));

                    return base.SendAsync(request, cancellationToken);
                }


                protected override void Dispose(bool disposing)
                {
                    base.Dispose(disposing);

                    if (disposing)
                    {
                    }
                }
            }
        }

        private class Domain
        {
            [JsonProperty("Name")]
            public string Name { get; set; }

            [JsonProperty("Type")]
            public string Type { get; set; }
        }


        private class DnsEntry
        {
            [JsonProperty("Name")]
            public string Name { get; set; }

            [JsonProperty("TTL")]
            public int Expire { get; set; }

            [JsonProperty("Type")]
            public string Type { get; set; }

            [JsonProperty("Data")]
            public string Content { get; set; }

            [JsonProperty("Remove")]
            public string Remove { get; set; }
        }
    }
}
