using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using static TUnit.Assertions.Assert;

namespace Nuskey.Net.Quic.Tests;

[NotInParallel]
public sealed class IntegrationTests
{
    [Test]
    public async Task Diagnostics_EmitsCompletedClientActivity()
    {
        await using var server = await TestServer.StartAsync();
        Activity? stopped = null;
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == QuicHttpHandlerDiagnostics.ActivitySourceName,
            Sample = static (ref ActivityCreationOptions<ActivityContext> _) =>
                ActivitySamplingResult.AllData,
            ActivityStopped = activity =>
            {
                if (Equals(activity.GetTagItem("server.port"), server.Port))
                    stopped = activity;
            },
        };
        ActivitySource.AddActivityListener(listener);
        using var handler = server.CreateHandler();
        using var client = new HttpClient(handler);

        using var response = await client.GetAsync(server.Uri("/"));
        await response.Content.ReadAsStringAsync();

        await That(stopped).IsNotNull();
        await That(stopped!.Kind).IsEqualTo(ActivityKind.Client);
        await That(stopped.GetTagItem("network.protocol.version")).IsEqualTo("3");
        await That(stopped.GetTagItem("http.response.status_code")).IsEqualTo(200);
        await That(stopped.Status).IsEqualTo(ActivityStatusCode.Ok);
    }

    [Test]
    public async Task Handler_ForcesHttp3WithoutFallback()
    {
        await using var server = await TestServer.StartAsync();
        using var handler = server.CreateHandler();
        using var client = new HttpClient(handler);
        using var request = new HttpRequestMessage(HttpMethod.Get, server.Uri("/"))
        {
            Version = HttpVersion.Version20,
            VersionPolicy = HttpVersionPolicy.RequestVersionOrLower,
        };

        using var response = await client.SendAsync(request);
        await That(response.Version).IsEqualTo(HttpVersion.Version30);
        await That(request.Version).IsEqualTo(HttpVersion.Version30);
        await That(request.VersionPolicy).IsEqualTo(HttpVersionPolicy.RequestVersionExact);
    }

    [Test]
    public async Task HostAddressOverrides_BypassesSystemDns()
    {
        await using var server = await TestServer.StartAsync();
        var uri = new UriBuilder(server.Uri("/")) { Host = "service.invalid" }.Uri;
        using var handler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            SkipCertificateVerification = true,
            HostAddressOverrides = new Dictionary<string, IReadOnlyList<IPAddress>>
            {
                ["service.invalid"] = new[] { IPAddress.Loopback },
            },
        };
        using var client = new HttpClient(handler);

        using var response = await client.GetAsync(uri);

        await That(response.StatusCode).IsEqualTo(HttpStatusCode.OK);
        await That(await response.Content.ReadAsStringAsync()).IsEqualTo("ok");
    }

    [Test]
    public async Task Diagnostics_ReportsConnectionPoolMetrics()
    {
        var measurements = new ConcurrentQueue<(string Name, long Value)>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, meterListener) =>
        {
            if (instrument.Meter.Name == QuicHttpHandlerDiagnostics.MeterName)
                meterListener.EnableMeasurementEvents(instrument);
        };
        listener.SetMeasurementEventCallback<long>(
            (instrument, value, _, _) => measurements.Enqueue((instrument.Name, value))
        );
        listener.Start();

        await using var server = await TestServer.StartAsync();
        using var handler = server.CreateHandler();
        using var client = new HttpClient(handler);

        using (var response = await client.GetAsync(server.Uri("/")))
            await response.Content.ReadAsStringAsync();

        listener.RecordObservableInstruments();
        await That(measurements)
            .Contains(x => x.Name == "quic.http.client.connections" && x.Value >= 1);
        await That(measurements)
            .Contains(x => x.Name == "quic.http.client.pool.requests" && x.Value >= 1);
    }

    [Test]
    public async Task KeepAlivePingPolicy_SendsQuicPingAndKeepsConnectionReusable()
    {
        await using var server = await TestServer.StartAsync();
        var qlog = new ConcurrentQueue<string>();
        using var handler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            SkipCertificateVerification = true,
            KeepAlivePingDelay = TimeSpan.FromMilliseconds(20),
            KeepAlivePingTimeout = TimeSpan.FromSeconds(1),
            KeepAlivePingPolicy = QuicKeepAlivePingPolicy.Always,
            QlogHandler = (_, json) => qlog.Enqueue(Encoding.UTF8.GetString(json)),
        };
        using var client = new HttpClient(handler);

        using (var response = await client.GetAsync(server.Uri("/")))
            await response.Content.ReadAsStringAsync();
        await Task.Delay(150);
        using (var response = await client.GetAsync(server.Uri("/")))
            await response.Content.ReadAsStringAsync();

        await That(await server.WaitForAcceptedConnectionsAsync(1)).IsTrue();
        await That(server.AcceptedConnectionCount).IsEqualTo(1);
        await That(qlog.Any(record => record.Contains("ping", StringComparison.OrdinalIgnoreCase)))
            .IsTrue();
    }

    [Test]
    public async Task QuicFlowControlAndPerformanceOptions_CompleteARequest()
    {
        await using var server = await TestServer.StartAsync();
        var qlog = new ConcurrentQueue<string>();
        using var handler = new QuicHttpHandler
        {
            SkipCertificateVerification = true,
            ResponsePipeOptions = new System.IO.Pipelines.PipeOptions(
                pauseWriterThreshold: 512 * 1024,
                resumeWriterThreshold: 256 * 1024,
                useSynchronizationContext: false
            ),
            QuicTransportOptions = new QuicTransportOptions
            {
                InitialMaxData = 2 * 1024 * 1024,
                InitialMaxStreamDataBidirectionalLocal = 512 * 1024,
                InitialMaxStreamDataBidirectionalRemote = 512 * 1024,
                InitialMaxStreamDataUnidirectional = 512 * 1024,
                InitialMaxStreamsBidirectional = 32,
                InitialMaxStreamsUnidirectional = 8,
                MaxConnectionWindow = 4 * 1024 * 1024,
                MaxStreamWindow = 2 * 1024 * 1024,
                SendBufferSize = 1024 * 1024,
                ReceiveBufferSize = 1024 * 1024,
                CongestionControlAlgorithm = QuicCongestionControlAlgorithm.Bbr2,
                InitialCongestionWindowPackets = 20,
                EnablePacing = true,
                MaxPacingRate = 100_000_000,
                DiscoverPathMtu = false,
                PmtudMaxProbes = 4,
                EnableHyStart = true,
                MaxSendUdpPayloadSize = 1452,
                MaxReceiveUdpPayloadSize = 1452,
                AckDelayExponent = 2,
                MaxAckDelay = TimeSpan.FromMilliseconds(20),
                SendCapacityFactor = 2,
            },
            QlogHandler = (_, json) => qlog.Enqueue(Encoding.UTF8.GetString(json)),
        };
        using var client = new HttpClient(handler);

        using var response = await client.GetAsync(server.Uri("/"));
        await That(await response.Content.ReadAsStringAsync()).IsEqualTo("ok");
        var trace = string.Join('\n', qlog);
        await That(trace.Contains("initial_max_data", StringComparison.Ordinal)).IsTrue();
    }

    [Test]
    public async Task CustomRootReplacement_TrustsOnlyTheConfiguredRoot()
    {
        await using var server = await TestServer.StartAsync();
        var certificatePem = server.CertificatePem;
        using var handler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            RootCertificates = certificatePem,
            RootCertificateMode = RootCertificateMode.Replace,
            OverrideServerName = "localhost",
        };
        using var client = new HttpClient(handler);

        using var response = await client.GetAsync(server.Uri("/"));
        await That(await response.Content.ReadAsStringAsync()).IsEqualTo("ok");
    }

    [Test]
    public async Task CertificateCallback_CanApplySubjectPublicKeyInfoPinning()
    {
        await using var server = await TestServer.StartAsync();
        var certificatePem = server.CertificatePem;
        using var certificate = X509Certificate2.CreateFromPem(certificatePem);
        var pin = SHA256.HashData(certificate.PublicKey.ExportSubjectPublicKeyInfo());
        using (
            var matchingHandler = new global::Nuskey.Net.Quic.QuicHttpHandler
            {
                RootCertificates = certificatePem,
                RootCertificateMode = RootCertificateMode.Replace,
                OverrideServerName = "localhost",
                OnVerifyServerCertificate = context =>
                    context.StandardVerificationSucceeded
                    && CryptographicOperations.FixedTimeEquals(
                        SHA256.HashData(context.Certificate.PublicKey.ExportSubjectPublicKeyInfo()),
                        pin
                    ),
            }
        )
        using (var matchingClient = new HttpClient(matchingHandler))
        using (var response = await matchingClient.GetAsync(server.Uri("/")))
            await That(await response.Content.ReadAsStringAsync()).IsEqualTo("ok");

        using var mismatchingHandler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            RootCertificates = certificatePem,
            RootCertificateMode = RootCertificateMode.Replace,
            OverrideServerName = "localhost",
            OnVerifyServerCertificate = context =>
                context.StandardVerificationSucceeded
                && CryptographicOperations.FixedTimeEquals(
                    SHA256.HashData(context.Certificate.PublicKey.ExportSubjectPublicKeyInfo()),
                    new byte[32]
                ),
        };
        using var mismatchingClient = new HttpClient(mismatchingHandler);
        await Assert.ThrowsAsync<HttpRequestException>(() =>
            mismatchingClient.GetAsync(server.Uri("/"))
        );
    }

    [Test]
    public async Task CertificateCallback_ReceivesStandardResultTimeAndChain()
    {
        await using var server = await TestServer.StartAsync();
        var certificatePem = server.CertificatePem;
        var called = false;
        using var handler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            RootCertificates = certificatePem,
            RootCertificateMode = RootCertificateMode.Replace,
            OverrideServerName = "localhost",
            OnVerifyServerCertificate = context =>
            {
                called = true;
                if (context.ServerName != "localhost")
                    return false;
                if (!context.StandardVerificationSucceeded)
                    return false;
                if (context.StandardVerificationErrorCode != 0)
                    return false;
                if (context.CertificateChain.Count == 0)
                    return false;
                if (context.VerificationTime < DateTimeOffset.UtcNow.AddMinutes(-1))
                    return false;
                return true;
            },
        };
        using var client = new HttpClient(handler);

        using var response = await client.GetAsync(server.Uri("/"));
        await That(await response.Content.ReadAsStringAsync()).IsEqualTo("ok");
        await That(called).IsTrue();
    }

    [Test]
    public async Task UntrustedCertificate_ThrowsHttpRequestException()
    {
        await using var server = await TestServer.StartAsync();
        using var handler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            RootCertificateMode = RootCertificateMode.Replace,
            OverrideServerName = "localhost",
        };
        using var client = new HttpClient(handler);

        await That(async () => await client.GetAsync(server.Uri("/")))
            .Throws<HttpRequestException>();
    }

    [Test]
    public async Task ClientCertificateAndPrivateKeyMismatch_IsRejectedBeforeHandshake()
    {
        await using var server = await TestServer.StartAsync();
        var certificatePem = server.CertificatePem;
        using var unrelatedKey = RSA.Create(2048);
        var unrelatedKeyPem = PemEncoding.WriteString(
            "PRIVATE KEY",
            unrelatedKey.ExportPkcs8PrivateKey()
        );
        using var handler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            SkipCertificateVerification = true,
            ClientAuthCertificates = certificatePem,
            ClientAuthKey = unrelatedKeyPem,
        };
        using var client = new HttpClient(handler);

        await Assert.ThrowsAsync<InvalidOperationException>(() => client.GetAsync(server.Uri("/")));
        await That(server.AcceptedConnectionCount).IsEqualTo(0);
    }

    [Test]
    public async Task Http3ApplicationError_ThrowsHttpRequestException()
    {
        await using var server = await TestServer.StartAsync();
        using var handler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            SkipCertificateVerification = true,
        };
        using var client = new HttpClient(handler);

        await That(async () => await client.GetAsync(server.Uri("/message-error")))
            .Throws<HttpRequestException>();
    }

    [Test]
    public async Task QlogHandler_ReceivesConnectionIdAndJsonRecords()
    {
        await using var server = await TestServer.StartAsync();
        var records = new ConcurrentQueue<(string ConnectionId, string Json)>();
        using var handler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            SkipCertificateVerification = true,
            QlogHandler = (connectionId, json) =>
                records.Enqueue(
                    (Encoding.UTF8.GetString(connectionId), Encoding.UTF8.GetString(json))
                ),
        };
        using var client = new HttpClient(handler);

        using var response = await client.GetAsync(server.Uri("/"));
        await That(await response.Content.ReadAsStringAsync()).IsEqualTo("ok");
        await That(records.IsEmpty).IsFalse();
        foreach (var record in records)
        {
            await That(string.IsNullOrWhiteSpace(record.ConnectionId)).IsFalse();
            using var json = JsonDocument.Parse(record.Json);
            await That(json.RootElement.ValueKind).IsEqualTo(JsonValueKind.Object);
        }
    }

    [Test]
    public async Task Qlog_LoggerExceptionDoesNotCrossTheNativeBoundary()
    {
        await using var server = await TestServer.StartAsync();
        using var handler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            SkipCertificateVerification = true,
            QlogHandler = (_, _) => throw new InvalidOperationException("handler failed"),
        };
        using var client = new HttpClient(handler);

        using var response = await client.GetAsync(server.Uri("/"));
        await That(await response.Content.ReadAsStringAsync()).IsEqualTo("ok");
    }

    [Test]
    public async Task ResponseTrailers_AreExposedToManagedCode()
    {
        await using var server = await TestServer.StartAsync();
        using var client = server.CreateClient();
        HttpResponseMessage response;
        try
        {
            response = await client.GetAsync(
                server.Uri("/trailers"),
                HttpCompletionOption.ResponseHeadersRead
            );
        }
        catch (Exception e)
        {
            throw new Exception($"{e.Message}\nSERVER:\n{server.Diagnostics}", e);
        }
        using (response)
        {
            await That(await response.Content.ReadAsStringAsync()).IsEqualTo("ok");
            await That(response.TrailingHeaders.GetValues("grpc-status").Single()).IsEqualTo("0");
            await That(response.TrailingHeaders.GetValues("grpc-message").Single()).IsEqualTo("ok");
        }
    }

    [Test]
    public async Task CancellationBeforeHeaders_ResetsTheQuicStream()
    {
        await using var server = await TestServer.StartAsync();
        using var client = server.CreateClient();
        using var cancellation = new CancellationTokenSource();

        var request = client.GetAsync(server.Uri("/delay-headers"), cancellation.Token);
        await That(await server.WaitForRequestAsync("/delay-headers")).IsTrue();
        cancellation.Cancel();
        await ExpectCancellation(() => request);
        await That(await server.WaitForResetAsync("/delay-headers")).IsTrue();
    }

    [Test]
    public async Task CancellationAfterHeaders_StopsResponseBody()
    {
        await using var server = await TestServer.StartAsync();
        using var client = server.CreateClient();
        using var cancellation = new CancellationTokenSource();
        using var response = await client.GetAsync(
            server.Uri("/stream"),
            HttpCompletionOption.ResponseHeadersRead,
            cancellation.Token
        );

        var bodyRead = response.Content.ReadAsByteArrayAsync(cancellation.Token);
        await That(await server.WaitForRequestAsync("/stream")).IsTrue();
        cancellation.Cancel();
        await ExpectCancellation(() => bodyRead);
        await That(await server.WaitForResetAsync("/stream")).IsTrue();
    }

    [Test]
    public async Task ResponseBodyBackpressure_PausesAndCanBeCancelled()
    {
        await using var server = await TestServer.StartAsync();
        using var handler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            SkipCertificateVerification = true,
            ResponsePipeOptions = new System.IO.Pipelines.PipeOptions(
                pauseWriterThreshold: 1,
                resumeWriterThreshold: 1,
                useSynchronizationContext: false
            ),
        };
        using var client = new HttpClient(handler);
        using var response = await client.GetAsync(
            server.Uri("/stream"),
            HttpCompletionOption.ResponseHeadersRead
        );

        await That(await server.WaitForRequestAsync("/stream")).IsTrue();
        await Task.Delay(150);
        response.Dispose();

        await That(await server.WaitForResetAsync("/stream")).IsTrue();
    }

    [Test]
    public async Task CancellationDuringUpload_ResetsTheQuicStream()
    {
        await using var server = await TestServer.StartAsync();
        using var client = server.CreateClient();
        using var cancellation = new CancellationTokenSource();
        using var request = new HttpRequestMessage(HttpMethod.Post, server.Uri("/upload"))
        {
            Content = new EndlessContent(),
        };

        var upload = client.SendAsync(
            request,
            HttpCompletionOption.ResponseHeadersRead,
            cancellation.Token
        );
        await That(await server.WaitForRequestAsync("/upload")).IsTrue();
        cancellation.Cancel();
        await ExpectCancellation(() => upload);
        await That(await server.WaitForResetAsync("/upload")).IsTrue();
    }

    [Test]
    public async Task HandlerDisposalDuringHandshake_CompletesAllQueuedRequests()
    {
        await using var server = await TestServer.StartAsync(blackhole: true);
        var handler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            SkipCertificateVerification = true,
            ConnectTimeout = TimeSpan.FromSeconds(30),
            HandshakeTimeout = TimeSpan.FromSeconds(30),
            MaxConnectionsPerServer = 1,
        };
        using var client = new HttpClient(handler);
        var requests = Enumerable
            .Range(0, 8)
            .Select(index => client.GetAsync(server.Uri($"/?id={index}")))
            .ToArray();

        await Task.Delay(100);
        handler.Dispose();
        var errors = await Task.WhenAll(
            requests.Select(task => ObserveFailure(task, TimeSpan.FromSeconds(5)))
        );

        await That(errors.All(error => error is OperationCanceledException or HttpRequestException))
            .IsTrue();
        await That(requests.All(task => task.IsCompleted)).IsTrue();
    }

    [Test]
    public async Task PooledConnectionIdleTimeout_ControlsConnectionReuse()
    {
        await using var server = await TestServer.StartAsync();
        using var handler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            SkipCertificateVerification = true,
            PooledConnectionIdleTimeout = TimeSpan.Zero,
        };
        using var client = new HttpClient(handler);

        using (var first = await client.GetAsync(server.Uri("/")))
            await That(first.IsSuccessStatusCode).IsTrue();
        using (var second = await client.GetAsync(server.Uri("/")))
            await That(second.IsSuccessStatusCode).IsTrue();

        await That(await server.WaitForAcceptedConnectionsAsync(2)).IsTrue();
    }

    [Test]
    public async Task PooledConnectionLifetime_ControlsConnectionReuse()
    {
        await using var server = await TestServer.StartAsync();
        using var handler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            SkipCertificateVerification = true,
            PooledConnectionIdleTimeout = Timeout.InfiniteTimeSpan,
            PooledConnectionLifetime = TimeSpan.Zero,
        };
        using var client = new HttpClient(handler);

        using (var first = await client.GetAsync(server.Uri("/")))
            await That(first.IsSuccessStatusCode).IsTrue();
        using (var second = await client.GetAsync(server.Uri("/")))
            await That(second.IsSuccessStatusCode).IsTrue();

        await That(await server.WaitForAcceptedConnectionsAsync(2)).IsTrue();
    }

    [Test]
    public async Task HappyEyeballs_FallsBackFromIpv6LocalhostToIpv4()
    {
        await using var server = await TestServer.StartAsync();
        using var handler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            SkipCertificateVerification = true,
            HappyEyeballsDelay = TimeSpan.FromMilliseconds(20),
        };
        using var client = new HttpClient(handler);

        using var response = await client.GetAsync(server.Uri("/", "localhost"));
        await That(await response.Content.ReadAsStringAsync()).IsEqualTo("ok");
    }

    [Test]
    public async Task ConnectTimeout_CompletesARequestToAnUnresponsiveEndpoint()
    {
        using var handler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            SkipCertificateVerification = true,
            ConnectTimeout = TimeSpan.FromMilliseconds(150),
            HandshakeTimeout = TimeSpan.FromSeconds(5),
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
        var timer = Stopwatch.StartNew();

        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync("https://192.0.2.1/"));
        await That(timer.Elapsed).IsLessThan(TimeSpan.FromSeconds(3));
    }

    [Test]
    public async Task HandshakeTimeout_CompletesARequestWhenUdpPeerDoesNotRespond()
    {
        await using var server = await TestServer.StartAsync(blackhole: true);
        using var handler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            SkipCertificateVerification = true,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            HandshakeTimeout = TimeSpan.FromMilliseconds(150),
        };
        using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(5) };
        var timer = Stopwatch.StartNew();

        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync(server.Uri("/")));
        await That(timer.Elapsed).IsLessThan(TimeSpan.FromSeconds(2));
    }

    [Test]
    public async Task ConnectionOptions_ValidateTheirRanges()
    {
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            Task.Run(() =>
                new global::Nuskey.Net.Quic.QuicHttpHandler { ConnectTimeout = TimeSpan.Zero }
            )
        );
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            Task.Run(() =>
                new global::Nuskey.Net.Quic.QuicHttpHandler
                {
                    HandshakeTimeout = Timeout.InfiniteTimeSpan,
                }
            )
        );
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            Task.Run(() =>
                new global::Nuskey.Net.Quic.QuicHttpHandler { DnsTimeout = TimeSpan.Zero }
            )
        );
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            Task.Run(() =>
                new global::Nuskey.Net.Quic.QuicHttpHandler
                {
                    DnsRefreshTimeout = TimeSpan.FromMilliseconds(-2),
                }
            )
        );
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            Task.Run(() =>
                new global::Nuskey.Net.Quic.QuicHttpHandler
                {
                    HappyEyeballsDelay = TimeSpan.FromMilliseconds(-1),
                }
            )
        );
        await Assert.ThrowsAsync<ArgumentOutOfRangeException>(() =>
            Task.Run(() =>
                new global::Nuskey.Net.Quic.QuicHttpHandler { MaxConnectionsPerServer = 0 }
            )
        );
        using var handler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            PooledConnectionIdleTimeout = Timeout.InfiniteTimeSpan,
            PooledConnectionLifetime = TimeSpan.Zero,
        };
    }

    [Test]
    public async Task QuicOptions_ValidateImmediateAndCorrelatedRanges()
    {
        await using var server = await TestServer.StartAsync();
        using var invalidFlowHandler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            SkipCertificateVerification = true,
            QuicTransportOptions = new QuicTransportOptions
            {
                InitialMaxData = 2 * 1024 * 1024,
                MaxConnectionWindow = 1024 * 1024,
            },
        };
        using var invalidFlowClient = new HttpClient(invalidFlowHandler);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            invalidFlowClient.GetAsync(server.Uri("/"))
        );

        using var invalidTransportHandler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            SkipCertificateVerification = true,
            QuicTransportOptions = new QuicTransportOptions { AckDelayExponent = 21 },
        };
        using var invalidTransportClient = new HttpClient(invalidTransportHandler);
        await Assert.ThrowsAsync<InvalidOperationException>(() =>
            invalidTransportClient.GetAsync(server.Uri("/"))
        );
    }

    [Test]
    public async Task MaxConnectionsPerServer_QueuesExcessRequestsInsteadOfOpeningAnotherConnection()
    {
        await using var server = await TestServer.StartAsync();
        using var handler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            SkipCertificateVerification = true,
            MaxConnectionsPerServer = 1,
        };
        using var client = new HttpClient(handler);

        var first = client.GetAsync(server.Uri("/slow"));
        await That(await server.WaitForRequestAsync("/slow")).IsTrue();
        var second = client.GetAsync(server.Uri("/slow"));
        using var firstResponse = await first;
        using var secondResponse = await second;

        await That(await server.WaitForAcceptedConnectionsAsync(1)).IsTrue();
        await That(server.AcceptedConnectionCount).IsEqualTo(1);
    }

    [Test]
    public async Task PeerMaxStreamsExhaustion_RoutesLaterRequestsToAnotherConnection()
    {
        await using var server = await TestServer.StartAsync(maxStreams: 1);
        using var handler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            SkipCertificateVerification = true,
            MaxConnectionsPerServer = 2,
        };
        using var client = new HttpClient(handler);

        var first = client.GetAsync(server.Uri("/slow"));
        await That(await server.WaitForRequestAsync("/slow")).IsTrue();
        var second = client.GetAsync(server.Uri("/slow"));
        await Task.Delay(100);
        var third = client.GetAsync(server.Uri("/slow"));
        using var firstResponse = await first;
        using var secondResponse = await second;
        using var thirdResponse = await third;

        await That(await server.WaitForAcceptedConnectionsAsync(2)).IsTrue();
    }

    [Test]
    public async Task ConnectionFailure_IsIsolatedFromOtherPooledConnections()
    {
        await using var server = await TestServer.StartAsync(maxStreams: 1);
        using var handler = new global::Nuskey.Net.Quic.QuicHttpHandler
        {
            SkipCertificateVerification = true,
            MaxConnectionsPerServer = 2,
        };
        using var client = new HttpClient(handler);

        var healthy = client.GetAsync(server.Uri("/slow"));
        await That(await server.WaitForRequestAsync("/slow")).IsTrue();
        await Assert.ThrowsAsync<HttpRequestException>(() => client.GetAsync(server.Uri("/abort")));
        using var response = await healthy.WaitAsync(TimeSpan.FromSeconds(5));
        await That(response.IsSuccessStatusCode).IsTrue();
    }

    [Test]
    public async Task HandlerDisposal_CompletesAllActiveRequests()
    {
        await using var server = await TestServer.StartAsync();
        var handler = server.CreateHandler();
        var client = new HttpClient(handler, disposeHandler: false);
        var request = client.GetAsync(server.Uri("/delay-headers"));
        await That(await server.WaitForRequestAsync("/delay-headers")).IsTrue();

        handler.Dispose();
        var completed = false;
        try
        {
            using var response = await request.WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (OperationCanceledException)
        {
            completed = true;
        }
        catch (HttpRequestException)
        {
            completed = true;
        }
        finally
        {
            client.Dispose();
        }
        await That(completed).IsTrue();
    }

    [Test]
    [Arguments(false)]
    [Arguments(true)]
    public async Task UploadFailure_IsObservedAndClosesTheRequest(bool asynchronous)
    {
        await using var server = await TestServer.StartAsync();
        using var client = server.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Post, server.Uri("/upload"))
        {
            Content = new ThrowingContent(asynchronous),
        };

        await Assert.ThrowsAsync<HttpRequestException>(() =>
            client.SendAsync(request).WaitAsync(TimeSpan.FromSeconds(5))
        );
        await Task.Delay(100);
        await That(server.AcceptedConnectionCount).IsLessThanOrEqualTo(1);
    }

    static async Task ExpectCancellation(Func<Task> operation)
    {
        var cancelled = false;
        try
        {
            await operation().WaitAsync(TimeSpan.FromSeconds(5));
        }
        catch (OperationCanceledException)
        {
            cancelled = true;
        }
        await That(cancelled).IsTrue();
    }

    static async Task<Exception?> ObserveFailure(Task operation, TimeSpan timeout)
    {
        try
        {
            await operation.WaitAsync(timeout);
            return null;
        }
        catch (Exception error)
        {
            return error;
        }
    }

    sealed class EndlessContent : HttpContent
    {
        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }

        protected override async Task SerializeToStreamAsync(
            Stream stream,
            System.Net.TransportContext? context
        )
        {
            var data = new byte[16 * 1024];
            while (true)
            {
                await stream.WriteAsync(data);
                await Task.Delay(10);
            }
        }
    }

    sealed class ThrowingContent(bool asynchronous) : HttpContent
    {
        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }

        protected override async Task SerializeToStreamAsync(
            Stream stream,
            System.Net.TransportContext? context
        )
        {
            if (asynchronous)
                await Task.Yield();
            throw new IOException("Expected upload failure.");
        }
    }
}

sealed class TestServer : IAsyncDisposable
{
    readonly Process process;
    readonly ConcurrentQueue<string> errors = new();
    public int Port { get; }
    public string CertificatePem { get; }
    public string Diagnostics => string.Join(Environment.NewLine, errors);
    public int AcceptedConnectionCount =>
        errors.Count(line => line.Contains("ACCEPTED", StringComparison.Ordinal));

    TestServer(Process process, int port, string certificatePem)
    {
        this.process = process;
        Port = port;
        CertificatePem = certificatePem;
        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data == null)
                return;
            errors.Enqueue(e.Data);
            Console.Error.WriteLine($"[test-server:{port}] {e.Data}");
        };
        process.BeginErrorReadLine();
    }

    public static async Task<TestServer> StartAsync(
        bool blackhole = false,
        ulong? maxStreams = null
    )
    {
        var root = FindRoot();
        var configuration = new DirectoryInfo(AppContext.BaseDirectory).Name;
        var serverAssembly = Path.Combine(
            root,
            "artifacts",
            "bin",
            "QuicHttpHandler.TestServer",
            configuration,
            "QuicHttpHandler.TestServer.dll"
        );
        var startInfo = new ProcessStartInfo("dotnet")
        {
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
        };
        if (OperatingSystem.IsMacOS())
        {
            const string homebrewLibraryPath = "/opt/homebrew/lib";
            if (File.Exists(Path.Combine(homebrewLibraryPath, "libmsquic.dylib")))
            {
                startInfo.Environment["DYLD_LIBRARY_PATH"] = string.Join(
                    Path.PathSeparator,
                    new[]
                    {
                        homebrewLibraryPath,
                        Environment.GetEnvironmentVariable("DYLD_LIBRARY_PATH"),
                    }.Where(value => !string.IsNullOrEmpty(value))
                );
            }
        }
        startInfo.ArgumentList.Add(serverAssembly);
        if (blackhole)
            startInfo.ArgumentList.Add("--blackhole");
        if (maxStreams.HasValue)
        {
            startInfo.ArgumentList.Add("--max-streams");
            startInfo.ArgumentList.Add(maxStreams.Value.ToString());
        }
        var process =
            Process.Start(startInfo)
            ?? throw new InvalidOperationException("Could not start HTTP/3 test server.");
        var line = await process.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(10));
        if (line == null || !line.StartsWith("PORT=", StringComparison.Ordinal))
        {
            var error = await process.StandardError.ReadToEndAsync();
            throw new InvalidOperationException($"Unexpected server output: {line}\n{error}");
        }
        var certificatePem = "";
        if (!blackhole)
        {
            var certificateLine = await process
                .StandardOutput.ReadLineAsync()
                .WaitAsync(TimeSpan.FromSeconds(10));
            if (
                certificateLine == null
                || !certificateLine.StartsWith("CERT=", StringComparison.Ordinal)
            )
                throw new InvalidOperationException(
                    $"Unexpected certificate output: {certificateLine}"
                );
            certificatePem = PemEncoding.WriteString(
                "CERTIFICATE",
                Convert.FromBase64String(certificateLine[5..])
            );
        }
        return new TestServer(process, int.Parse(line.AsSpan(5)), certificatePem);
    }

    public Uri Uri(string path, string host = "127.0.0.1") => new($"https://{host}:{Port}{path}");

    public global::Nuskey.Net.Quic.QuicHttpHandler CreateHandler() =>
        new() { SkipCertificateVerification = true };

    public HttpClient CreateClient()
    {
        return new HttpClient(CreateHandler()) { Timeout = TimeSpan.FromSeconds(15) };
    }

    public async Task<bool> WaitForResetAsync(string path)
    {
        var timeout = Stopwatch.StartNew();
        while (timeout.Elapsed < TimeSpan.FromSeconds(5))
        {
            if (
                errors.Any(line =>
                    line.Contains($"RESET {path}", StringComparison.Ordinal)
                    || line.Contains($"SEND_STOP {path}", StringComparison.Ordinal)
                    || line.Contains($"RECV_STOP {path}", StringComparison.Ordinal)
                    || line.Contains($"CLOSED {path}", StringComparison.Ordinal)
                )
            )
                return true;
            await Task.Delay(20);
        }
        return false;
    }

    public async Task<bool> WaitForRequestAsync(string path)
    {
        var timeout = Stopwatch.StartNew();
        while (timeout.Elapsed < TimeSpan.FromSeconds(5))
        {
            if (errors.Any(line => line.Contains($"REQUEST {path}", StringComparison.Ordinal)))
                return true;
            await Task.Delay(20);
        }
        return false;
    }

    public async Task<bool> WaitForAcceptedConnectionsAsync(int count)
    {
        var timeout = Stopwatch.StartNew();
        while (timeout.Elapsed < TimeSpan.FromSeconds(5))
        {
            if (errors.Count(line => line.Contains("ACCEPTED", StringComparison.Ordinal)) >= count)
                return true;
            await Task.Delay(20);
        }
        return false;
    }

    public ValueTask DisposeAsync()
    {
        if (!process.HasExited)
            process.Kill(entireProcessTree: true);
        process.Dispose();
        return ValueTask.CompletedTask;
    }

    static string FindRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (
            directory != null
            && !File.Exists(Path.Combine(directory.FullName, "QuicHttpHandler.slnx"))
        )
            directory = directory.Parent;
        return directory?.FullName
            ?? throw new DirectoryNotFoundException("Repository root not found.");
    }
}
