using GrpcOverHttp3.Server;
using Microsoft.AspNetCore.Server.Kestrel.Core;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseQuic();

using var serverCertificate = LocalhostCertificate.Create();

builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenLocalhost(
        5001,
        listenOptions =>
        {
            listenOptions.Protocols = HttpProtocols.Http3;
            listenOptions.UseHttps(serverCertificate);
        }
    );
});
builder.Services.AddGrpc();

var app = builder.Build();
app.MapGrpcService<GreeterService>();
await app.RunAsync();
