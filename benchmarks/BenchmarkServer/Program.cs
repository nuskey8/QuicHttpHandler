using System.Net;
using Microsoft.AspNetCore.Server.Kestrel.Core;

var port = int.Parse(args[0]);
var builder = WebApplication.CreateSlimBuilder(args);
builder.Logging.ClearProviders();
builder.WebHost.UseQuic();

using var certificate = LocalhostCertificate.Create();

builder.WebHost.ConfigureKestrel(options =>
    options.Listen(
        IPAddress.Loopback,
        port,
        listen =>
        {
            listen.Protocols = HttpProtocols.Http2 | HttpProtocols.Http3;
            listen.UseHttps(certificate);
        }
    )
);

var app = builder.Build();
var large = new byte[1024 * 1024];
app.MapGet("/", () => "ok");
app.MapGet("/large", () => Results.Bytes(large));
await app.StartAsync();
Console.WriteLine("READY");
await app.WaitForShutdownAsync();
