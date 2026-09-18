using MagicOnion;
using MagicOnion.Server;
using MagicOnionServer1.Shared;

namespace MagicOnionServer1.Server;

public sealed class HelloService : ServiceBase<IHelloService>, IHelloService
{
    public UnaryResult<string> HelloAsync(string name) =>
        UnaryResult.FromResult($"Hello, {name} from gRPC over HTTP/3!");
}
