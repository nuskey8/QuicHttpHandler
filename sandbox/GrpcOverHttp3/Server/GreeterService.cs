using Grpc.Core;
using GrpcOverHttp3;

namespace GrpcOverHttp3.Server;

internal sealed class GreeterService : Greeter.GreeterBase
{
    public override Task<HelloReply> SayHello(HelloRequest request, ServerCallContext context) =>
        Task.FromResult(
            new HelloReply { Message = $"Hello, {request.Name}, from gRPC over HTTP/3!" }
        );
}
