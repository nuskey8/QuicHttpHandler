# QuicHttpHandler
Provides HTTP/3 support for .NET Standard and Unity.

[![NuGet](https://img.shields.io/nuget/v/QuicHttpHandler.svg)](https://www.nuget.org/packages/QuicHttpHandler)
[![Releases](https://img.shields.io/github/release/nuskey8/QuicHttpHandler.svg)](https://github.com/nuskey8/QuicHttpHandler/releases)
[![license](https://img.shields.io/badge/LICENSE-MIT-green.svg)](LICENSE)

[English](./README.md) | 日本語

## 概要

QuicHttpHandlerは.NET Standard / Unity向けのHTTP/3サポートを提供するライブラリです。

現在の.NETではMsQuicをベースとしたHTTP/3がサポートされていますが、Unityなどの古いランタイムでは利用できません。QuicHttpHandlerは[quiche](https://github.com/cloudflare/quiche)をベースとしたRust実装をFFIでC#に持ち込むことにより、HTTP/3サポートを提供します。

> [!CAUTION]
> このライブラリは現在アルファ版であり、本番環境での利用は推奨されません。

## インストール

### NuGet

```sh
dotnet package add QuicHttpHandler
```

### Unity

> [!NOTE]
> ネイティブプラグインを含む都合上、パッケージの配布方法が異なることに注意してください。

Unityの場合、Package Managerからのインストールが可能です。

1. Window > Package ManagerからPackage Managerを開く
2. 「+」ボタン > Add package from git URL
3. 以下のURLを入力する

```
https://github.com/nuskey8/QuicHttpHandler.git?path=src/QuicHttpHandler.Unity/Packages/QuicHttpHandler.Unity
```

加えて、以下の依存dllをプロジェクトに追加する必要があります。これには[NugetForUnity](https://github.com/GlitchEnzo/NuGetForUnity)が便利です。

- System.Diagnostics.DiagnosticSource 10.0.0 以上
- System.IO.Pipelines 10.0.0 以上

## 使い方

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

## HTTP/1.1、HTTP/2へのフォールバック

`QuicHttpHandler`はHTTP/3のみをサポートしています。HTTP/1.1、HTTP/2を同時にサポートしたい場合は`DelegatingHandler`を用いて別の実装にフォールバックさせてください。以下は`UnityHttpMessageHandler`と組み合わせて利用するhandler実装のサンプルです。

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

## 設定

TODO:

## ライセンス

このライブラリは[MIT LICENSE](LICENSE)の下で提供されています。quicheなどのサードパーティのライセンスについてはそれぞれのリポジトリを参照してください。
