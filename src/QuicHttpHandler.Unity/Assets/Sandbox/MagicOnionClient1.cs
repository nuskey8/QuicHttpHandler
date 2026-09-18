using System;
using System.Threading;
using Grpc.Net.Client;
using MagicOnion.Client;
using MagicOnionServer1.Shared;
using Nuskey.Net.Quic;
using UnityEngine;

[MagicOnionClientGeneration(typeof(IHelloService))]
internal partial class MagicOnionGeneratedClientInitializer { }

public sealed class MagicOnionClient1 : MonoBehaviour
{
    [SerializeField]
    string playerName = "Unity";

    GrpcChannel channel;

    async void Start()
    {
        try
        {
            channel = GrpcChannel.ForAddress(
                "https://localhost:5002",
                new GrpcChannelOptions
                {
                    HttpHandler = new QuicHttpHandler { SkipCertificateVerification = true },
                    DisposeHttpClient = true,
                }
            );

            var client = MagicOnionClient.Create<IHelloService>(channel);
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(
                destroyCancellationToken
            );
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            var message = await client.WithCancellationToken(timeout.Token).HelloAsync(playerName);
            Debug.Log(message, this);
        }
        catch (OperationCanceledException) when (destroyCancellationToken.IsCancellationRequested)
        { }
        catch (Exception exception)
        {
            Debug.LogException(exception, this);
        }
    }

    void OnDestroy()
    {
        channel?.Dispose();
    }
}
