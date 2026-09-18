using System.Net;
using BenchmarkDotNet.Attributes;
using Nuskey.Net.Quic;

public enum Http3HandlerKind
{
    QuicHttpHandler,
    SocketsHttpHandler,
}

[MemoryDiagnoser]
public class Http3Benchmarks
{
    BenchmarkServerProcess? server;
    HttpClient? client;
    Uri? root;
    Uri? large;

    [Params(Http3HandlerKind.QuicHttpHandler, Http3HandlerKind.SocketsHttpHandler)]
    public Http3HandlerKind Handler { get; set; }

    [Params(8, 64)]
    public int Concurrency { get; set; }

    [GlobalSetup]
    public async Task Setup()
    {
        server = await BenchmarkServerProcess.StartAsync();
        root = server.Root;
        large = new Uri(root, "large");
        HttpMessageHandler handler = Handler switch
        {
            Http3HandlerKind.QuicHttpHandler => new QuicHttpHandler
            {
                SkipCertificateVerification = true,
                MaxConnectionsPerServer = 8,
            },
            Http3HandlerKind.SocketsHttpHandler => new SocketsHttpHandler
            {
                SslOptions = new System.Net.Security.SslClientAuthenticationOptions
                {
                    RemoteCertificateValidationCallback = static (_, _, _, _) => true,
                },
            },
            _ => throw new ArgumentOutOfRangeException(),
        };
        client = new HttpClient(handler);
        await DrainAsync(root);
    }

    [Benchmark(Baseline = true)]
    public Task SmallResponse() => DrainAsync(root!);

    [Benchmark]
    public Task OneMiBResponse() => DrainAsync(large!);

    [Benchmark]
    public Task ConcurrentSmallResponses() =>
        Task.WhenAll(Enumerable.Range(0, Concurrency).Select(_ => DrainAsync(root!)));

    async Task DrainAsync(Uri uri)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, uri)
        {
            Version = HttpVersion.Version30,
            VersionPolicy = HttpVersionPolicy.RequestVersionExact,
        };
        using var response = await client!.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead
        );
        await response.Content.CopyToAsync(Stream.Null);
    }

    [GlobalCleanup]
    public void Cleanup()
    {
        client?.Dispose();
        server?.Dispose();
    }

    internal static string FindRepositoryRoot()
    {
        for (
            var directory = new DirectoryInfo(AppContext.BaseDirectory);
            directory != null;
            directory = directory.Parent
        )
        {
            if (File.Exists(Path.Combine(directory.FullName, "Cargo.toml")))
                return directory.FullName;
        }
        throw new DirectoryNotFoundException("Repository root not found.");
    }
}
