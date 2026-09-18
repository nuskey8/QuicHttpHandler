using System;
using System.Net.Http;
using System.Threading;
using Nuskey.Net.Quic;
using UnityEngine;

public sealed class Sandbox : MonoBehaviour
{
    static readonly Uri Endpoint = new("https://www.cloudflare.com/cdn-cgi/trace");

    readonly CancellationTokenSource lifetime = new();
    HttpClient client;

    async void Start()
    {
        try
        {
            client = new HttpClient(new QuicHttpHandler());
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(lifetime.Token);
            timeout.CancelAfter(TimeSpan.FromSeconds(15));

            using var response = await client.GetAsync(
                Endpoint,
                HttpCompletionOption.ResponseHeadersRead,
                timeout.Token
            );
            var body = await response.Content.ReadAsStringAsync();

            Debug.Log(
                $"Cloudflare HTTP/{response.Version} "
                    + $"{(int)response.StatusCode} {response.ReasonPhrase}\n{body}"
            );
        }
        catch (OperationCanceledException) when (lifetime.IsCancellationRequested)
        {
            // The component or its GameObject was destroyed.
        }
        catch (Exception exception)
        {
            Debug.LogException(exception, this);
        }
    }

    void OnDestroy()
    {
        lifetime.Cancel();
        client?.Dispose();
        lifetime.Dispose();
    }
}
