using Nuskey.Net.Quic;

using var handler = new QuicHttpHandler();
using var client = new HttpClient(handler);
using var response = await client.GetAsync(
    "https://cloudflare-quic.com/",
    HttpCompletionOption.ResponseHeadersRead
);

var text = await response.Content.ReadAsStringAsync();

Console.WriteLine($"{text}");
