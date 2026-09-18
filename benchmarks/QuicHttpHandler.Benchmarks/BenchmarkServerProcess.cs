using System.Diagnostics;
using System.Net;
using System.Net.Sockets;

sealed class BenchmarkServerProcess : IDisposable
{
    readonly Process process;

    BenchmarkServerProcess(Process process, Uri root)
    {
        this.process = process;
        Root = root;
    }

    public Uri Root { get; }

    public static async Task<BenchmarkServerProcess> StartAsync()
    {
        var repositoryRoot = Http3Benchmarks.FindRepositoryRoot();
        var serverDll = Path.Combine(
            repositoryRoot,
            "benchmarks/BenchmarkServer/bin/Release/net10.0/BenchmarkServer.dll"
        );
        if (!File.Exists(serverDll))
            throw new FileNotFoundException("Build BenchmarkServer in Release first.", serverDll);

        var port = GetAvailablePort();
        var process =
            Process.Start(
                new ProcessStartInfo("dotnet", $"\"{serverDll}\" {port}")
                {
                    WorkingDirectory = repositoryRoot,
                    RedirectStandardOutput = true,
                    RedirectStandardError = true,
                    UseShellExecute = false,
                }
            ) ?? throw new InvalidOperationException("Could not start the benchmark server.");
        process.ErrorDataReceived += static (_, _) => { };
        process.BeginErrorReadLine();

        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        while (await process.StandardOutput.ReadLineAsync(timeout.Token) is { } line)
            if (line == "READY")
                return new BenchmarkServerProcess(process, new Uri($"https://127.0.0.1:{port}/"));

        process.Dispose();
        throw new InvalidOperationException("Benchmark server exited before becoming ready.");
    }

    static int GetAvailablePort()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        return ((IPEndPoint)listener.LocalEndpoint).Port;
    }

    public void Dispose()
    {
        if (!process.HasExited)
            process.Kill(entireProcessTree: true);
        process.Dispose();
    }
}
