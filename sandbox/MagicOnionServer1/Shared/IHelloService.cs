using MagicOnion;

namespace MagicOnionServer1.Shared
{
    public interface IHelloService : IService<IHelloService>
    {
        UnaryResult<string> HelloAsync(string name);
    }
}
