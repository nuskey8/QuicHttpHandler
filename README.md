# QuicHttpHandler
Provides HTTP/3 support for .NET Standard and Unity.

[![NuGet](https://img.shields.io/nuget/v/QuicHttpHandler.svg)](https://www.nuget.org/packages/QuicHttpHandler)
[![Releases](https://img.shields.io/github/release/nuskey8/QuicHttpHandler.svg)](https://github.com/nuskey8/QuicHttpHandler/releases)
[![license](https://img.shields.io/badge/LICENSE-MIT-green.svg)](LICENSE)

English | [日本語](./README_JA.md)

## Overview

QuicHttpHandler is a library that provides HTTP/3 support for .NET Standard and Unity.

Modern .NET supports HTTP/3 through an MsQuic-based implementation, but it is unavailable on older runtimes such as Unity. QuicHttpHandler provides HTTP/3 support by bringing a Rust implementation based on [quiche](https://github.com/cloudflare/quiche) into C# through FFI.

> [!CAUTION]
> This library is currently in alpha and is not recommended for production use.

## Installation

### NuGet

```sh
dotnet package add QuicHttpHandler
```

### Unity

> [!NOTE]
> The distribution method differs because the package includes native plug-ins.

You can install the Unity package through Package Manager.

1. Open Package Manager from Window > Package Manager.
2. Select the "+" button > Add package from git URL.
3. Enter the following URL:

```
https://github.com/nuskey8/QuicHttpHandler.git?path=src/QuicHttpHandler.Unity/Packages/QuicHttpHandler.Unity
```

You must also add the following dependency DLLs to your project. [NuGetForUnity](https://github.com/GlitchEnzo/NuGetForUnity) is useful for installing them.

- System.Diagnostics.DiagnosticSource 10.0.0 or later
- System.IO.Pipelines 10.0.0 or later

## Usage

```csharp
using Nuskey.Net.Quic;

using var handler = new QuicHttpHandler();
using var client = new HttpClient(handler);
using var response = await client.GetAsync(
    "https://cloudflare-quic.com/",
    HttpCompletionOption.ResponseHeadersRead
);

var text = await response.Content.ReadAsStringAsync();
Console.WriteLine(text);
```

## HTTP/1.1 and HTTP/2 fallback

`QuicHttpHandler` supports HTTP/3 only. To support HTTP/1.1 and HTTP/2 at the same time, use a `DelegatingHandler` to fall back to another implementation. The following is an example handler that combines `QuicHttpHandler` with `UnityHttpMessageHandler`.

```csharp
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Nuskey.Net.Quic;
using UnityEngine.Networking;

public sealed class ExampleHandler : DelegatingHandler
{
    readonly HttpMessageInvoker http3;

    public ExampleHandler()
        : base(new UnityHttpMessageHandler())
    {
        http3 = new HttpMessageInvoker(
            new QuicHttpHandler(),
            disposeHandler: true
        );
    }

    protected override Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken
    )
    {
        if (request.Version.Major >= 3)
            return http3.SendAsync(request, cancellationToken);

        return base.SendAsync(request, cancellationToken);
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
            http3.Dispose();

        base.Dispose(disposing);
    }
}
```

## Configuration

TODO:

## License

This library is available under the [MIT License](LICENSE). Refer to the respective repositories for the licenses of quiche and other third-party components.
