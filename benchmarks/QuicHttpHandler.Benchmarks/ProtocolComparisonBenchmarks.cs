using System.Net;
using BenchmarkDotNet.Attributes;
using Nuskey.Net.Quic;

public enum ProtocolHandlerKind
{
    QuicHttpHandlerHttp3,
    SocketsHttpHandlerHttp3,
    SocketsHttpHandlerHttp2,
}

[MemoryDiagnoser]
public class ProtocolComparisonBenchmarks
{
    BenchmarkServerProcess? server;
    HttpClient? client;
    Uri? root;
    Version? version;

    [ParamsAllValues]
    public ProtocolHandlerKind Handler { get; set; }

    [GlobalSetup]
    public async Task Setup()
    {
        server = await BenchmarkServerProcess.StartAsync();
        root = server.Root;
        var (handler, protocol) = CreateHandler();
        version = protocol;
        client = new HttpClient(handler);
        await DrainAsync();
    }

    [Benchmark]
    public Task SmallResponse() => DrainAsync();

    async Task DrainAsync()
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, root!)
        {
            Version = version!,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
        using var response = await client!.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead
        );
        await response.Content.CopyToAsync(Stream.Null);
    }

    (HttpMessageHandler Handler, Version Protocol) CreateHandler() =>
        Handler switch
        {
            ProtocolHandlerKind.QuicHttpHandlerHttp3 => (
                new QuicHttpHandler { SkipCertificateVerification = true },
                HttpVersion.Version30
            ),
            ProtocolHandlerKind.SocketsHttpHandlerHttp3 => (
                CreateSocketsHandler(),
                HttpVersion.Version30
            ),
            ProtocolHandlerKind.SocketsHttpHandlerHttp2 => (
                CreateSocketsHandler(),
                HttpVersion.Version20
            ),
            _ => throw new ArgumentOutOfRangeException(),
        };

    static SocketsHttpHandler CreateSocketsHandler() =>
        new()
        {
            SslOptions = new System.Net.Security.SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = static (_, _, _, _) => true,
            },
        };

    [GlobalCleanup]
    public void Cleanup()
    {
        client?.Dispose();
        server?.Dispose();
    }
}
