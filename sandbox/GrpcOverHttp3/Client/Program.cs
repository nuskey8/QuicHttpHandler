using System.Net;
using Grpc.Net.Client;
using GrpcOverHttp3;
using Nuskey.Net.Quic;

using var handler = new QuicHttpHandler
{
    // The example server uses a self-signed localhost certificate.
    SkipCertificateVerification = true,
};
using var channel = GrpcChannel.ForAddress(
    "https://localhost:5001",
    new GrpcChannelOptions
    {
        HttpHandler = handler,
        HttpVersion = HttpVersion.Version30,
        HttpVersionPolicy = HttpVersionPolicy.RequestVersionExact,
    }
);

var client = new Greeter.GreeterClient(channel);
var reply = await client.SayHelloAsync(
    new HelloRequest { Name = "Alice" },
    deadline: DateTime.UtcNow.AddSeconds(10)
);

Console.WriteLine(reply.Message);
