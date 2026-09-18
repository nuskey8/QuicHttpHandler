using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using ConsoleAppFramework;
using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core;

await ConsoleApp.RunAsync(args, RunServerAsync);

static async Task RunServerAsync(
    bool blackhole = false,
    int? maxStreams = null,
    CancellationToken cancellationToken = default
)
{
    if (blackhole)
    {
        using var socket = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        Console.WriteLine($"PORT={((IPEndPoint)socket.Client.LocalEndPoint!).Port}");
        Console.Out.Flush();
        while (!cancellationToken.IsCancellationRequested)
            await socket.ReceiveAsync(cancellationToken);
        return;
    }

    var port = ReserveUdpPort();
    using var certificate = LocalhostCertificate.Create();
    var connections = new ConcurrentDictionary<string, byte>();

    var builder = WebApplication.CreateBuilder();
    builder.Logging.ClearProviders();
    builder.WebHost.UseQuic(options =>
    {
        if (maxStreams.HasValue)
            options.MaxBidirectionalStreamCount = maxStreams.Value;
    });
    builder.WebHost.ConfigureKestrel(options =>
    {
        options.Listen(
            IPAddress.Loopback,
            port,
            endpoint =>
            {
                endpoint.Protocols = HttpProtocols.Http3;
                endpoint.UseHttps(certificate);
            }
        );
    });

    var app = builder.Build();
    app.Run(async context =>
    {
        var path = context.Request.Path + context.Request.QueryString;
        var route = context.Request.Path.Value ?? "/";
        var connectionId = context.Connection.Id;
        if (connections.TryAdd(connectionId, 0))
            Console.Error.WriteLine("ACCEPTED");
        Console.Error.WriteLine($"REQUEST {path}");
        context.RequestAborted.Register(() => Console.Error.WriteLine($"RESET {path}"));

        switch (route)
        {
            case "/delay-headers":
                await Task.Delay(500, context.RequestAborted);
                break;
            case "/slow":
                await Task.Delay(500, context.RequestAborted);
                await context.Response.WriteAsync("ok", context.RequestAborted);
                return;
            case "/stream":
                await context.Response.StartAsync(context.RequestAborted);
                await context.Response.WriteAsync("started", context.RequestAborted);
                await context.Response.Body.FlushAsync(context.RequestAborted);
                try
                {
                    while (true)
                    {
                        await Task.Delay(50, context.RequestAborted);
                        await context.Response.WriteAsync("next", context.RequestAborted);
                        await context.Response.Body.FlushAsync(context.RequestAborted);
                    }
                }
                catch (OperationCanceledException)
                {
                    Console.Error.WriteLine($"SEND_STOP {path}");
                }
                return;
            case "/upload":
                try
                {
                    await context.Request.Body.CopyToAsync(Stream.Null, context.RequestAborted);
                    await Task.Delay(TimeSpan.FromSeconds(10), context.RequestAborted);
                }
                catch (OperationCanceledException)
                {
                    Console.Error.WriteLine($"RECV_STOP {path}");
                }
                return;
            case "/trailers":
                context.Response.DeclareTrailer("grpc-status");
                context.Response.DeclareTrailer("grpc-message");
                await context.Response.WriteAsync("ok", context.RequestAborted);
                context.Response.AppendTrailer("grpc-status", "0");
                context.Response.AppendTrailer("grpc-message", "ok");
                return;
            case "/abort":
                Console.Error.WriteLine("ABORT_EXECUTED");
                context.Features.Get<IConnectionLifetimeFeature>()?.Abort();
                return;
            case "/message-error":
                context.Features.Get<IHttpResetFeature>()?.Reset(0x010e);
                return;
        }

        await context.Response.WriteAsync("ok", context.RequestAborted);
    });

    await app.StartAsync(cancellationToken);
    Console.WriteLine($"PORT={port}");
    Console.WriteLine($"CERT={Convert.ToBase64String(certificate.RawData)}");
    Console.Out.Flush();
    await app.WaitForShutdownAsync(cancellationToken);
}

static int ReserveUdpPort()
{
    using var socket = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
    return ((IPEndPoint)socket.Client.LocalEndPoint!).Port;
}
