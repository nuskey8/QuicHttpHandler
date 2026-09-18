using Microsoft.AspNetCore.Server.Kestrel.Core;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseQuic();

using var certificate = LocalhostCertificate.Create();
builder.WebHost.ConfigureKestrel(options =>
{
    options.ListenLocalhost(
        5002,
        listen =>
        {
            listen.Protocols = HttpProtocols.Http3;
            listen.UseHttps(certificate);
        }
    );
});

builder.Services.AddMagicOnion();

var app = builder.Build();
app.MapMagicOnionService();
await app.RunAsync();
