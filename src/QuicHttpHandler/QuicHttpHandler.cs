using System;
using System.Buffers;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Pipelines;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Nuskey.Net.Quic.Interop;
using InteropContext = Nuskey.Net.Quic.Interop.Context;
using InteropRequest = Nuskey.Net.Quic.Interop.Request;

namespace Nuskey.Net.Quic;

/// <summary>A Unity-compatible, quiche-backed HTTP/3 message handler.</summary>
public sealed class QuicHttpHandler : HttpMessageHandler
{
    static unsafe class NativeCallbacks
    {
        internal static readonly NativeMethods.qhh_context_new_on_headers_delegate Headers =
            OnHeaders;
        internal static readonly NativeMethods.qhh_context_new_on_body_delegate Body = OnBody;
        internal static readonly NativeMethods.qhh_context_new_on_trailers_delegate Trailers =
            OnTrailers;
        internal static readonly NativeMethods.qhh_context_new_on_informational_headers_delegate InformationalHeaders =
            OnInformationalHeaders;
        internal static readonly NativeMethods.qhh_context_new_on_complete_delegate Complete =
            OnComplete;
        internal static readonly NativeMethods.qhh_context_set_tls_options_verify_callback_delegate VerifyCertificate =
            QuicHttpHandler.VerifyCertificate;
        internal static readonly NativeMethods.qhh_context_set_qlog_callback_delegate Qlog =
            WriteQlog;
    }

    static readonly Version Http3Version = new(3, 0);

#if NET_9_0_OR_GREATER
    readonly Lock gate = new();
#else
    readonly object gate = new();
#endif

    readonly ConcurrentDictionary<RequestState, byte> activeRequests = new();
    NativeContext? context;
    bool disposed;

    public ServerCertificateVerificationHandler? OnVerifyServerCertificate { get; init; }
    public bool SkipCertificateVerification { get; init; }
    public string? RootCertificates { get; init; }
    public RootCertificateMode RootCertificateMode { get; init; }
    public string? OverrideServerName { get; init; }
    public string? ClientAuthCertificates { get; init; }
    public string? ClientAuthKey { get; init; }
    public IReadOnlyDictionary<string, IReadOnlyList<IPAddress>> HostAddressOverrides
    {
        get;
        init
        {
            Guard.NotNull(value, nameof(HostAddressOverrides));
            field = value;
        }
    } = new Dictionary<string, IReadOnlyList<IPAddress>>();
    public TimeSpan ConnectTimeout
    {
        get;
        init
        {
            Guard.PositiveTimeout(value, nameof(ConnectTimeout));
            field = value;
        }
    } = TimeSpan.FromSeconds(10);
    public TimeSpan HandshakeTimeout
    {
        get;
        init
        {
            Guard.PositiveTimeout(value, nameof(HandshakeTimeout));
            field = value;
        }
    } = TimeSpan.FromSeconds(10);
    public TimeSpan PooledConnectionIdleTimeout
    {
        get;
        init
        {
            Guard.NonNegativeOrInfiniteTimeout(value, nameof(PooledConnectionIdleTimeout));
            field = value;
        }
    } = TimeSpan.FromMinutes(2);
    public TimeSpan PooledConnectionLifetime
    {
        get;
        init
        {
            Guard.NonNegativeOrInfiniteTimeout(value, nameof(PooledConnectionLifetime));
            field = value;
        }
    } = Timeout.InfiniteTimeSpan;
    public TimeSpan DnsTimeout
    {
        get;
        init
        {
            Guard.PositiveTimeout(value, nameof(DnsTimeout));
            field = value;
        }
    } = TimeSpan.FromSeconds(5);
    public TimeSpan DnsRefreshTimeout
    {
        get;
        init
        {
            Guard.PositiveTimeout(value, nameof(DnsRefreshTimeout));
            field = value;
        }
    } = TimeSpan.FromMinutes(1);
    public TimeSpan HappyEyeballsDelay
    {
        get;
        init
        {
            Guard.NonNegativeTimeout(value, nameof(HappyEyeballsDelay));
            field = value;
        }
    } = TimeSpan.FromMilliseconds(250);

    public TimeSpan KeepAlivePingDelay
    {
        get;
        init
        {
            Guard.PositiveOrInfiniteTimeout(value, nameof(KeepAlivePingDelay));
            field = value;
        }
    } = Timeout.InfiniteTimeSpan;

    public TimeSpan KeepAlivePingTimeout
    {
        get;
        init
        {
            Guard.PositiveTimeout(value, nameof(KeepAlivePingTimeout));
            field = value;
        }
    } = TimeSpan.FromSeconds(20);

    public QuicKeepAlivePingPolicy KeepAlivePingPolicy { get; init; }

    public int MaxConnectionsPerServer
    {
        get;
        init
        {
            Guard.Positive(value, nameof(MaxConnectionsPerServer));
            field = value;
        }
    } = 4;

    public PipeOptions ResponsePipeOptions
    {
        get;
        init
        {
            Guard.NotNull(value, nameof(ResponsePipeOptions));
            field = value;
        }
    } =
        new(
            pauseWriterThreshold: 262144,
            resumeWriterThreshold: 131072,
            useSynchronizationContext: false
        );

    public QuicTransportOptions QuicTransportOptions
    {
        get;
        init
        {
            Guard.NotNull(value, nameof(QuicTransportOptions));
            field = value;
        }
    } = QuicTransportOptions.Default;

    public long MaxHeaderListSize
    {
        get;
        init
        {
            Guard.Positive(value, nameof(MaxHeaderListSize));
            field = value;
        }
    } = 32768;

    public long QpackMaxTableCapacity
    {
        get;
        init
        {
            Guard.NonNegative(value, nameof(QpackMaxTableCapacity));
            field = value;
        }
    }

    public long QpackBlockedStreams
    {
        get;
        init
        {
            Guard.NonNegative(value, nameof(QpackBlockedStreams));
            field = value;
        }
    }

    public bool EnableExtendedConnect { get; init; }
    public bool EnableEarlyData { get; init; }
    public QlogEventHandler? QlogHandler { get; init; }
    public InformationalResponseHandler? OnInformationalResponse { get; init; }

    public int WorkerThreads
    {
        get;
        init
        {
            Guard.NonNegative(value, nameof(WorkerThreads));
            field = value;
        }
    }

    protected override unsafe Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request,
        CancellationToken cancellationToken
    )
    {
        if (request is null)
            throw new ArgumentNullException(nameof(request));

        var requestUri = request.RequestUri;
        if (requestUri == null)
            throw new InvalidOperationException("RequestUri is required.");
        if (!requestUri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
            throw new NotSupportedException("HTTP/3 requires an HTTPS URI.");

        cancellationToken.ThrowIfCancellationRequested();

        request.Version = Http3Version;
#if NET5_0_OR_GREATER
        request.VersionPolicy = HttpVersionPolicy.RequestVersionExact;
#endif

        var state = new RequestState(this, request, cancellationToken);
        NativeContext nativeContext;
        lock (gate)
        {
            nativeContext = GetContextWithoutLock();
            activeRequests.TryAdd(state, 0);
        }
        try
        {
            state.Start(nativeContext.Context);
        }
        catch
        {
            state.Cancel();
            throw;
        }
        return state.ResponseTask;
    }

    NativeContext GetContextWithoutLock()
    {
        if (disposed)
            throw new ObjectDisposedException(nameof(QuicHttpHandler));

        if (context != null)
            return context;
        var nativeContext = new NativeContext(
            this,
            WorkerThreads,
            NativeCallbacks.Headers,
            NativeCallbacks.Body,
            NativeCallbacks.Trailers,
            NativeCallbacks.InformationalHeaders,
            NativeCallbacks.Complete
        );
        QuicHttpHandlerDiagnostics.Register(this);
        return context = nativeContext;
    }

    internal ConnectionPoolStatistics GetConnectionPoolStatisticsForDiagnostics()
    {
        lock (gate)
        {
            return context?.GetPoolStatistics() ?? default;
        }
    }

    internal unsafe void ConfigureNativeContext(InteropContext* nativeContext, void* callbackState)
    {
        ConfigureConnection(nativeContext);
        ConfigureDnsOverrides(nativeContext);
        ConfigureQuic(nativeContext);
        ConfigureHttp3(nativeContext);
        ConfigureQlog(nativeContext, callbackState);
        ConfigureTls(nativeContext, callbackState);
    }

    unsafe void ConfigureConnection(InteropContext* nativeContext)
    {
        if (
            !NativeMethods.qhh_context_set_connection_options(
                nativeContext,
                ToMilliseconds(ConnectTimeout),
                ToMilliseconds(HandshakeTimeout),
                ToMilliseconds(PooledConnectionIdleTimeout),
                ToMilliseconds(PooledConnectionLifetime),
                ToMilliseconds(DnsTimeout),
                ToMilliseconds(DnsRefreshTimeout),
                ToMilliseconds(HappyEyeballsDelay),
                ToMilliseconds(KeepAlivePingDelay),
                ToMilliseconds(KeepAlivePingTimeout),
                KeepAlivePingPolicy == QuicKeepAlivePingPolicy.Always,
                checked((nuint)MaxConnectionsPerServer)
            )
        )
            throw new InvalidOperationException("Invalid native connection configuration.");
    }

    unsafe void ConfigureDnsOverrides(InteropContext* nativeContext)
    {
        foreach (var entry in HostAddressOverrides)
        {
            if (string.IsNullOrWhiteSpace(entry.Key))
                throw new ArgumentException(
                    "DNS override host names cannot be empty.",
                    nameof(HostAddressOverrides)
                );
            if (entry.Value == null || entry.Value.Count == 0)
                throw new ArgumentException(
                    "Each DNS override must contain at least one IP address.",
                    nameof(HostAddressOverrides)
                );

            var host = Encoding.UTF8.GetBytes(entry.Key);
            var addresses = Encoding.UTF8.GetBytes(string.Join(",", entry.Value));
            fixed (
                byte* h = host,
                    a = addresses
            )
            {
                if (
                    !NativeMethods.qhh_context_set_dns_override(
                        nativeContext,
                        h,
                        (nuint)host.Length,
                        a,
                        (nuint)addresses.Length
                    )
                )
                    throw new ArgumentException(
                        "Invalid DNS override.",
                        nameof(HostAddressOverrides)
                    );
            }
        }
    }

    static ulong ToMilliseconds(TimeSpan value)
    {
        return value == Timeout.InfiniteTimeSpan
            ? ulong.MaxValue
            : checked((ulong)Math.Ceiling(value.TotalMilliseconds));
    }

    async Task UploadAsync(
        HttpContent content,
        Stream destination,
        RequestState state,
        CancellationToken cancellationToken
    )
    {
        using (destination)
        {
            try
            {
#if NET8_0_OR_GREATER
                await content.CopyToAsync(destination, cancellationToken).ConfigureAwait(false);
#else
                await content.CopyToAsync(destination).ConfigureAwait(false);
#endif
                state.CompleteUpload();
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                state.Cancel();
            }
            catch (Exception error)
            {
                state.Fail(error);
            }
        }
    }

    static async Task CopyResponseAsync(
        PipeReader source,
        Stream destination,
        RequestState state,
        CancellationToken cancellationToken
    )
    {
        try
        {
            await source.CopyToAsync(destination, cancellationToken).ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            state.Cancel();
            throw;
        }
    }

    static async Task AwaitBodyFlushAsync(RequestState state, ValueTask<FlushResult> flush)
    {
        try
        {
            state.ResumeBodyAfterFlush(await flush.ConfigureAwait(false));
        }
        catch (Exception error)
        {
            state.Fail(error);
        }
    }

    protected override void Dispose(bool disposing)
    {
        NativeContext? nativeContext;
        lock (gate)
        {
            if (disposed)
                return;
            disposed = true;

            nativeContext = context;
            context = null;
        }

        foreach (var request in activeRequests.Keys)
        {
            request.Cancel();
        }

        nativeContext?.Dispose();
        base.Dispose(disposing);
    }

    void RemoveActiveRequest(RequestState request) => activeRequests.TryRemove(request, out _);

    unsafe void ConfigureTls(InteropContext* nativeContext, void* callbackState)
    {
        if (ClientAuthCertificates == null != (ClientAuthKey == null))
        {
            throw new InvalidOperationException(
                "ClientAuthCertificates and ClientAuthKey must be configured together."
            );
        }

        var custom = !SkipCertificateVerification && OnVerifyServerCertificate != null;
        byte[]? name = null;
        byte[]? roots = null;
        byte[]? certificates = null;
        byte[]? key = null;
        try
        {
            name = RentUtf8(OverrideServerName, out var nameLength);
            roots = RentUtf8(RootCertificates, out var rootsLength);
            certificates = RentUtf8(ClientAuthCertificates, out var certificatesLength);
            key = RentUtf8(ClientAuthKey, out var keyLength);
            fixed (
                byte* n = name,
                    r = roots,
                    c = certificates,
                    k = key
            )
            {
                if (
                    !NativeMethods.qhh_context_set_tls_options(
                        nativeContext,
                        SkipCertificateVerification,
                        custom,
                        RootCertificateMode == RootCertificateMode.Replace,
                        n,
                        (nuint)nameLength,
                        r,
                        (nuint)rootsLength,
                        c,
                        (nuint)certificatesLength,
                        k,
                        (nuint)keyLength,
                        callbackState,
                        NativeCallbacks.VerifyCertificate
                    )
                )
                    throw new InvalidOperationException("Invalid native TLS configuration.");
            }
        }
        finally
        {
            ReturnPooledBuffer(name);
            ReturnPooledBuffer(roots);
            ReturnPooledBuffer(certificates);
            ReturnPooledBuffer(key);
        }
    }

    unsafe void ConfigureQlog(InteropContext* nativeContext, void* callbackState)
    {
        if (
            QlogHandler != null
            && !NativeMethods.qhh_context_set_qlog(
                nativeContext,
                callbackState,
                NativeCallbacks.Qlog
            )
        )
            throw new InvalidOperationException("Invalid native qlog configuration.");
    }

    unsafe void ConfigureQuic(InteropContext* nativeContext)
    {
        var options = QuicTransportOptions;
        Guard.QuicTransport(options);
        Guard.QuicFlowControl(
            options.InitialMaxData,
            options.InitialMaxStreamDataBidirectionalLocal,
            options.InitialMaxStreamDataBidirectionalRemote,
            options.InitialMaxStreamDataUnidirectional,
            options.MaxConnectionWindow,
            options.MaxStreamWindow
        );

        if (
            !NativeMethods.qhh_context_set_quic_flow_control(
                nativeContext,
                checked((ulong)options.InitialMaxData),
                checked((ulong)options.InitialMaxStreamDataBidirectionalLocal),
                checked((ulong)options.InitialMaxStreamDataBidirectionalRemote),
                checked((ulong)options.InitialMaxStreamDataUnidirectional),
                checked((ulong)options.InitialMaxStreamsBidirectional),
                checked((ulong)options.InitialMaxStreamsUnidirectional),
                checked((ulong)options.MaxConnectionWindow),
                checked((ulong)options.MaxStreamWindow),
                checked((nuint)options.SendBufferSize),
                checked((nuint)options.ReceiveBufferSize)
            )
            || !NativeMethods.qhh_context_set_quic_performance(
                nativeContext,
                checked((byte)options.CongestionControlAlgorithm),
                checked((nuint)options.InitialCongestionWindowPackets),
                options.EnablePacing,
                options.MaxPacingRate ?? 0,
                options.DiscoverPathMtu,
                options.PmtudMaxProbes,
                options.EnableHyStart,
                checked((nuint)options.MaxSendUdpPayloadSize),
                checked((nuint)options.MaxReceiveUdpPayloadSize),
                options.AckDelayExponent,
                checked((ulong)Math.Ceiling(options.MaxAckDelay.TotalMilliseconds)),
                options.SendCapacityFactor,
                EnableEarlyData
            )
        )
        {
            throw new InvalidOperationException("Invalid native QUIC configuration.");
        }
    }

    unsafe void ConfigureHttp3(InteropContext* nativeContext)
    {
        if (
            !NativeMethods.qhh_context_set_http3_options(
                nativeContext,
                checked((ulong)MaxHeaderListSize),
                checked((ulong)QpackMaxTableCapacity),
                checked((ulong)QpackBlockedStreams),
                EnableExtendedConnect
            )
        )
            throw new InvalidOperationException("Invalid native HTTP/3 configuration.");
    }

#if UNITY_2019_1_OR_NEWER
    [AOT.MonoPInvokeCallback(typeof(NativeMethods.qhh_context_set_qlog_callback_delegate))]
#endif
    static unsafe byte WriteQlog(
        void* state,
        byte* connectionId,
        nuint connectionIdLength,
        byte* json,
        nuint jsonLength
    )
    {
        try
        {
            var handler = GetHandler(state);
            var qlogHandler = handler.QlogHandler;
            if (qlogHandler == null)
                return 0;
            var connectionIdSpan = new ReadOnlySpan<byte>(
                connectionId,
                checked((int)connectionIdLength)
            );
            var jsonSpan = new ReadOnlySpan<byte>(json, checked((int)jsonLength));
            qlogHandler(connectionIdSpan, jsonSpan);
            return 1;
        }
        catch
        {
            return 0;
        }
    }

    static byte[]? RentUtf8(string? value, out int length)
    {
        if (string.IsNullOrEmpty(value))
        {
            length = 0;
            return null;
        }

        length = Encoding.UTF8.GetByteCount(value);
        var buffer = ArrayPool<byte>.Shared.Rent(length);
        Encoding.UTF8.GetBytes(value.AsSpan(), buffer);
        return buffer;
    }

    static void ReturnPooledBuffer(byte[]? buffer)
    {
        if (buffer != null)
            ArrayPool<byte>.Shared.Return(buffer, clearArray: true);
    }

#if UNITY_2019_1_OR_NEWER
    [AOT.MonoPInvokeCallback(
        typeof(NativeMethods.qhh_context_set_tls_options_verify_callback_delegate)
    )]
#endif
    static unsafe byte VerifyCertificate(
        void* state,
        byte* serverName,
        nuint serverNameLength,
        byte* certificate,
        nuint certificateLength,
        byte* certificateChain,
        nuint certificateChainLength,
        byte standardVerificationSucceeded,
        int standardVerificationErrorCode,
        long verificationTimeUnixMilliseconds
    )
    {
        try
        {
            var handler = GetHandler(state);
            var certificateSpan = new ReadOnlySpan<byte>(
                certificate,
                checked((int)certificateLength)
            );

            var verify = handler.OnVerifyServerCertificate;
            if (verify == null)
                return standardVerificationSucceeded;

            var name = Encoding.UTF8.GetString(
                new ReadOnlySpan<byte>(serverName, checked((int)serverNameLength))
            );
            var certificates = DecodeCertificateChain(
                new ReadOnlySpan<byte>(certificateChain, checked((int)certificateChainLength))
            );
            try
            {
                var leaf =
                    certificates.Count == 0 ? LoadCertificate(certificateSpan) : certificates[0];
                var ownsLeaf = certificates.Count == 0;
                try
                {
                    return verify(
                        new ServerCertificateVerificationContext(
                            name,
                            leaf,
                            certificates,
                            DateTimeOffset.FromUnixTimeMilliseconds(
                                verificationTimeUnixMilliseconds
                            ),
                            standardVerificationSucceeded != 0,
                            standardVerificationErrorCode
                        )
                    )
                        ? (byte)1
                        : (byte)0;
                }
                finally
                {
                    if (ownsLeaf)
                        leaf.Dispose();
                }
            }
            finally
            {
                foreach (var item in certificates)
                    item.Dispose();
            }
        }
        catch
        {
            return 0;
        }
    }

    static unsafe QuicHttpHandler GetHandler(void* state) =>
        (QuicHttpHandler)(
            GCHandle.FromIntPtr((IntPtr)state).Target
            ?? throw new InvalidOperationException("Native callback state is unavailable.")
        );

    static List<X509Certificate2> DecodeCertificateChain(ReadOnlySpan<byte> encoded)
    {
        var certificates = new List<X509Certificate2>();
        while (!encoded.IsEmpty)
        {
            if (encoded.Length < sizeof(int))
                throw new InvalidOperationException("Invalid native certificate chain.");
            var length = encoded[0] | (encoded[1] << 8) | (encoded[2] << 16) | (encoded[3] << 24);
            encoded = encoded[sizeof(int)..];
            if (length <= 0 || length > encoded.Length)
                throw new InvalidOperationException("Invalid native certificate chain.");
            certificates.Add(LoadCertificate(encoded[..length]));
            encoded = encoded[length..];
        }
        return certificates;
    }

    static X509Certificate2 LoadCertificate(ReadOnlySpan<byte> raw)
    {
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadCertificate(raw);
#else
        return new X509Certificate2(raw.ToArray());
#endif
    }

#if UNITY_2019_1_OR_NEWER
    [AOT.MonoPInvokeCallback(typeof(NativeMethods.qhh_context_new_on_headers_delegate))]
#endif
    static unsafe byte OnHeaders(void* state, uint status, byte* data, nuint length)
    {
        try
        {
            return RequestState
                .FromCallbackState(state)
                .HandleHeaders(status, data, checked((int)length));
        }
        catch
        {
            // Exceptions must never cross the unmanaged callback boundary.
            return 0;
        }
    }

#if UNITY_2019_1_OR_NEWER
    [AOT.MonoPInvokeCallback(typeof(NativeMethods.qhh_context_new_on_body_delegate))]
#endif
    static unsafe byte OnBody(void* state, byte* data, nuint length)
    {
        try
        {
            return RequestState.FromCallbackState(state).HandleBody(data, checked((int)length));
        }
        catch
        {
            // Exceptions must never cross the unmanaged callback boundary.
            return 2;
        }
    }

#if UNITY_2019_1_OR_NEWER
    [AOT.MonoPInvokeCallback(typeof(NativeMethods.qhh_context_new_on_trailers_delegate))]
#endif
    static unsafe byte OnTrailers(void* state, byte* data, nuint length)
    {
        try
        {
            return RequestState.FromCallbackState(state).HandleTrailers(data, checked((int)length));
        }
        catch
        {
            // Exceptions must never cross the unmanaged callback boundary.
            return 0;
        }
    }

#if UNITY_2019_1_OR_NEWER
    [AOT.MonoPInvokeCallback(
        typeof(NativeMethods.qhh_context_new_on_informational_headers_delegate)
    )]
#endif
    static unsafe byte OnInformationalHeaders(void* state, uint status, byte* data, nuint length)
    {
        try
        {
            return RequestState
                .FromCallbackState(state)
                .HandleInformationalHeaders(status, data, checked((int)length));
        }
        catch
        {
            // Exceptions must never cross the unmanaged callback boundary.
            return 0;
        }
    }

#if UNITY_2019_1_OR_NEWER
    [AOT.MonoPInvokeCallback(typeof(NativeMethods.qhh_context_new_on_complete_delegate))]
#endif
    static unsafe void OnComplete(
        void* state,
        int code,
        int errorKind,
        ulong _,
        byte* error,
        nuint length
    )
    {
        try
        {
            RequestState
                .FromCallbackState(state)
                .HandleCompletion(code, errorKind, error, checked((int)length));
        }
        catch
        {
            // Exceptions must never cross the unmanaged callback boundary.
        }
    }

    internal sealed unsafe class RequestState
    {
#if NET_9_0_OR_GREATER
        readonly Lock gate = new();
#else
        readonly object gate = new();
#endif
        readonly QuicHttpHandler owner;
        readonly HttpRequestMessage request;
        readonly CancellationToken token;
        Pipe? pipe;
        readonly TaskCompletionSource<HttpResponseMessage> response = new(
            TaskCreationOptions.RunContinuationsAsynchronously
        );
        GCHandle gcHandle;
        InteropRequest* native;
        InteropRequest* deferredNativeDispose;
        int activeNativeOperations;
        CancellationTokenRegistration registration;
        HttpResponseMessage? responseMessage;
        Exception? callbackError;
        bool completed;
        readonly long startedAt = Stopwatch.GetTimestamp();
        readonly Activity? activity;

        internal RequestState(
            QuicHttpHandler owner,
            HttpRequestMessage request,
            CancellationToken token
        )
        {
            this.owner = owner;
            this.request = request;
            this.token = token;
            activity = QuicHttpHandlerDiagnostics.Start(request);
            QuicHttpHandlerDiagnostics.Requests.Add(1);
            QuicHttpHandlerDiagnostics.ActiveRequests.Add(1);
        }

        internal Task<HttpResponseMessage> ResponseTask => response.Task;

        internal static RequestState FromCallbackState(void* value) =>
            (RequestState)(
                GCHandle.FromIntPtr((IntPtr)value).Target
                ?? throw new InvalidOperationException("Native request state is unavailable.")
            );

        internal void Start(InteropContext* context)
        {
            lock (gate)
            {
                if (completed)
                    return;
                gcHandle = GCHandle.Alloc(this);
                var newRegistration = token.Register(static x => ((RequestState)x!).Cancel(), this);
                registration = newRegistration;
                if (completed)
                {
                    newRegistration.Dispose();
                    return;
                }
                StartAttempt(context);
            }
        }

        void StartAttempt(InteropContext* context)
        {
            var methodText = request.Method.Method;
            byte[]? rentedMethod = null;
            ReadOnlySpan<byte> method = methodText switch
            {
                "GET" => "GET"u8,
                "POST" => "POST"u8,
                "PUT" => "PUT"u8,
                "DELETE" => "DELETE"u8,
                "HEAD" => "HEAD"u8,
                "OPTIONS" => "OPTIONS"u8,
                "PATCH" => "PATCH"u8,
                "TRACE" => "TRACE"u8,
                "CONNECT" => "CONNECT"u8,
                _ => EncodeCustomMethod(methodText, out rentedMethod),
            };

            var uri = request.RequestUri!;
            var hostText = uri.IdnHost;
            var authorityText = uri.Authority;
            var pathText = uri.PathAndQuery;
            var hostLength = Encoding.UTF8.GetByteCount(hostText);
            var authorityLength = Encoding.UTF8.GetByteCount(authorityText);
            var pathLength = Encoding.UTF8.GetByteCount(pathText);
            var headersLength = EncodedHeadersLength(request);
            var payloadLength = checked(hostLength + authorityLength + pathLength + headersLength);
            byte[]? payload = null;
            try
            {
                payload = ArrayPool<byte>.Shared.Rent(Math.Max(payloadLength, 1));
                var payloadSpan = payload.AsSpan(0, payloadLength);
                Encoding.UTF8.GetBytes(hostText.AsSpan(), payloadSpan[..hostLength]);
                Encoding.UTF8.GetBytes(
                    authorityText.AsSpan(),
                    payloadSpan.Slice(hostLength, authorityLength)
                );
                Encoding.UTF8.GetBytes(
                    pathText.AsSpan(),
                    payloadSpan.Slice(hostLength + authorityLength, pathLength)
                );
                EncodeHeaders(request, payloadSpan[(hostLength + authorityLength + pathLength)..]);
                fixed (
                    byte* m = method,
                        p = payload
                )
                {
                    native = NativeMethods.qhh_send(
                        context,
                        (void*)GCHandle.ToIntPtr(gcHandle),
                        m,
                        (nuint)method.Length,
                        p,
                        (nuint)hostLength,
                        checked((ushort)uri.Port),
                        p + hostLength,
                        (nuint)authorityLength,
                        p + hostLength + authorityLength,
                        (nuint)pathLength,
                        p + hostLength + authorityLength + pathLength,
                        (nuint)headersLength,
                        request.Content != null,
                        owner.EnableEarlyData && IsEarlyDataEligible(request)
                    );
                }
            }
            finally
            {
                if (rentedMethod != null)
                    ArrayPool<byte>.Shared.Return(rentedMethod);
                if (payload != null)
                    ArrayPool<byte>.Shared.Return(payload);
            }

            if (native == null)
                return;

            if (request.Content != null)
                _ = owner.UploadAsync(request.Content, new UploadStream(this), this, token);
        }

        static ReadOnlySpan<byte> EncodeCustomMethod(string method, out byte[] rented)
        {
            var length = Encoding.UTF8.GetByteCount(method);
            rented = ArrayPool<byte>.Shared.Rent(Math.Max(length, 1));
            var encoded = rented.AsSpan(0, length);
            Encoding.UTF8.GetBytes(method.AsSpan(), encoded);
            return encoded;
        }

        static bool IsEarlyDataEligible(HttpRequestMessage request) =>
            request.Content == null
            && request.Method.Method is "GET" or "HEAD" or "OPTIONS" or "TRACE"
            && request.Headers.Authorization == null
            && !request.Headers.Contains("Cookie")
            && !request.Headers.Contains("Proxy-Authorization");

        internal void CompleteUpload()
        {
            InteropRequest* requestToFinish;
            lock (gate)
            {
                if (completed || native == null)
                    return;
                requestToFinish = native;
                activeNativeOperations++;
            }
            try
            {
                NativeMethods.qhh_request_finish(requestToFinish);
            }
            finally
            {
                ReleaseNativeOperation();
            }
        }

        internal byte HandleHeaders(uint status, byte* data, int length)
        {
            try
            {
                lock (gate)
                {
                    if (completed)
                        return 1;

                    var message = new HttpResponseMessage((HttpStatusCode)status)
                    {
                        RequestMessage = request,
                        Version = Http3Version,
                        Content = new ResponseContent(
                            this,
                            (pipe ??= new Pipe(owner.ResponsePipeOptions)).Reader
                        ),
                    };
                    AddHeaders(message, data, length, trailers: false);
                    responseMessage = message;
                    activity?.SetTag("http.response.status_code", (int)status);
                    response.TrySetResult(message);
                    return 1;
                }
            }
            catch (Exception e)
            {
                return RecordCallbackFailure(e, 0);
            }
        }

        internal byte HandleTrailers(byte* data, int length)
        {
            try
            {
                lock (gate)
                {
                    if (completed || responseMessage == null)
                        return 1;
                    AddHeaders(responseMessage, data, length, trailers: true);
                    return 1;
                }
            }
            catch (Exception e)
            {
                return RecordCallbackFailure(e, 0);
            }
        }

        internal byte HandleInformationalHeaders(uint status, byte* data, int length)
        {
            try
            {
                if (Volatile.Read(ref completed))
                    return 1;

                var callback = owner.OnInformationalResponse;
                if (callback == null)
                    return 1;

                var headers = DecodeInformationalHeaders(data, length);
                callback(request, status, headers);
                return 1;
            }
            catch (Exception e)
            {
                return RecordCallbackFailure(e, 0);
            }
        }

        internal byte HandleBody(byte* data, int length)
        {
            try
            {
                lock (gate)
                {
                    if (completed)
                        return 1;
                    var writer = pipe?.Writer;
                    if (writer == null)
                        throw new InvalidOperationException(
                            "Received an HTTP/3 response body before its headers."
                        );
                    new ReadOnlySpan<byte>(data, length).CopyTo(writer.GetSpan(length));
                    writer.Advance(length);
                    var flush = writer.FlushAsync(token);
                    if (flush.IsCompletedSuccessfully)
                    {
                        var result = flush.Result;
                        if (result.IsCanceled || result.IsCompleted)
                            return 0;
                        return 1;
                    }

                    _ = AwaitBodyFlushAsync(this, flush);
                    return 0;
                }
            }
            catch (Exception e)
            {
                return RecordCallbackFailure(e, 2);
            }
        }

        byte RecordCallbackFailure(Exception error, byte result)
        {
            Interlocked.CompareExchange(ref callbackError, error, null);
            return result;
        }

        internal void ResumeBodyAfterFlush(FlushResult result)
        {
            if (result.IsCanceled || result.IsCompleted)
                return;

            lock (gate)
            {
                if (!completed && native != null)
                    NativeMethods.qhh_request_resume_body(native);
            }
        }

        internal void HandleCompletion(int code, int errorKind, byte* error, int length)
        {
            var managedError = Volatile.Read(ref callbackError);
            if (managedError != null)
            {
                Finish(managedError);
                return;
            }
            var completionCode = (NativeCompletionCode)code;
            var message =
                length == 0 ? null : Encoding.UTF8.GetString(new ReadOnlySpan<byte>(error, length));
            Finish(CreateCompletionException(completionCode, errorKind, message));
        }

        Exception? CreateCompletionException(
            NativeCompletionCode completionCode,
            int errorKind,
            string? message
        )
        {
            if (completionCode == NativeCompletionCode.Success)
                return null;
            if (completionCode == NativeCompletionCode.Cancelled)
                return new OperationCanceledException(token);
            return new HttpRequestException(
                message
                    ?? (
                        (NativeErrorKind)errorKind == NativeErrorKind.TlsHandshake
                            ? "TLS handshake failed."
                        : completionCode
                            is NativeCompletionCode.ConnectionDraining
                                or NativeCompletionCode.ConnectionFailureBeforeHeaders
                                or NativeCompletionCode.RequestRejected
                            ? "HTTP/3 request was not processed and can be retried."
                        : "HTTP/3 request failed."
                    )
            );
        }

        internal bool Write(ReadOnlySpan<byte> data)
        {
            InteropRequest* requestToWrite;
            lock (gate)
            {
                if (completed || native == null)
                    return false;
                requestToWrite = native;
                activeNativeOperations++;
            }
            fixed (byte* pointer = data)
            {
                try
                {
                    return NativeMethods.qhh_request_write(
                        requestToWrite,
                        pointer,
                        (nuint)data.Length
                    );
                }
                finally
                {
                    ReleaseNativeOperation();
                }
            }
        }

        void ReleaseNativeOperation()
        {
            InteropRequest* requestToDispose = null;
            lock (gate)
            {
                activeNativeOperations--;
                if (activeNativeOperations == 0)
                {
                    requestToDispose = deferredNativeDispose;
                    deferredNativeDispose = null;
                }
            }
            if (requestToDispose != null)
                NativeMethods.qhh_request_dispose(requestToDispose);
        }

        internal void Cancel() => Finish(new OperationCanceledException(token), cancelNative: true);

        internal void Fail(Exception error) => Finish(error, cancelNative: true);

        void Finish(Exception? error, bool cancelNative = false)
        {
            InteropRequest* requestToCancel;
            InteropRequest* requestToDispose;

            lock (gate)
            {
                if (completed)
                    return;

                completed = true;
                requestToCancel = cancelNative ? native : null;
                deferredNativeDispose = native;
                if (requestToCancel != null)
                    activeNativeOperations++;
                if (activeNativeOperations == 0)
                {
                    requestToDispose = deferredNativeDispose;
                    deferredNativeDispose = null;
                }
                else
                {
                    requestToDispose = null;
                }
                native = null;
                pipe?.Writer.Complete(error);
                if (error != null)
                    response.TrySetException(error);
            }

            if (requestToCancel != null)
            {
                try
                {
                    NativeMethods.qhh_request_cancel(requestToCancel);
                }
                finally
                {
                    ReleaseNativeOperation();
                }
            }
            if (requestToDispose != null)
                NativeMethods.qhh_request_dispose(requestToDispose);

            var elapsed = (Stopwatch.GetTimestamp() - startedAt) * 1000.0 / Stopwatch.Frequency;
            QuicHttpHandlerDiagnostics.Duration.Record(elapsed);
            QuicHttpHandlerDiagnostics.ActiveRequests.Add(-1);
            if (error != null)
            {
                QuicHttpHandlerDiagnostics.Failures.Add(1);
                activity?.SetStatus(ActivityStatusCode.Error, error.Message);
                activity?.SetTag("error.type", error.GetType().FullName);
            }
            else
            {
                activity?.SetStatus(ActivityStatusCode.Ok);
            }
            activity?.Dispose();

            registration.Dispose();
            if (gcHandle.IsAllocated)
                gcHandle.Free();
            owner.RemoveActiveRequest(this);
        }

        internal void Abandon()
        {
            Cancel();
            pipe?.Reader.Complete();
        }

        static int EncodedHeadersLength(HttpRequestMessage request)
        {
            var length = EncodedLength(request.Headers);
            if (request.Content != null)
                length = checked(length + EncodedLength(request.Content.Headers));
            return length;
        }

        static void EncodeHeaders(HttpRequestMessage request, Span<byte> destination)
        {
            var offset = 0;
            Encode(request.Headers, destination, ref offset);
            if (request.Content != null)
                Encode(request.Content.Headers, destination, ref offset);
        }

        static int EncodedLength(HttpHeaders source)
        {
            var length = 0;
            foreach (var header in source)
            {
                if (ExcludedHeader(header.Key))
                    continue;

                foreach (var value in header.Value)
                {
                    length = checked(
                        length + header.Key.Length + Encoding.UTF8.GetByteCount(value) + 2
                    );
                }
            }
            return length;
        }

        static void Encode(HttpHeaders source, Span<byte> destination, ref int offset)
        {
            foreach (var header in source)
            {
                if (ExcludedHeader(header.Key))
                    continue;
                foreach (var value in header.Value)
                {
                    foreach (var character in header.Key)
                    {
                        destination[offset++] = character is >= 'A' and <= 'Z'
                            ? (byte)(character + ('a' - 'A'))
                            : (byte)character;
                    }
                    destination[offset++] = 0;
                    offset += Encoding.UTF8.GetBytes(value.AsSpan(), destination[offset..]);
                    destination[offset++] = 0;
                }
            }
        }

        static bool ExcludedHeader(string name) =>
            name.Equals("host", StringComparison.OrdinalIgnoreCase)
            || name.Equals("connection", StringComparison.OrdinalIgnoreCase)
            || name.Equals("keep-alive", StringComparison.OrdinalIgnoreCase)
            || name.Equals("proxy-connection", StringComparison.OrdinalIgnoreCase)
            || name.Equals("transfer-encoding", StringComparison.OrdinalIgnoreCase)
            || name.Equals("upgrade", StringComparison.OrdinalIgnoreCase);

        static void AddHeaders(HttpResponseMessage message, byte* data, int length, bool trailers)
        {
            var span = new ReadOnlySpan<byte>(data, length);
            var start = 0;
            while (start < length)
            {
                var nameLength = span[start..].IndexOf((byte)0);
                if (nameLength < 0)
                    break;

                var valueStart = start + nameLength + 1;
                var valueLength = span[valueStart..].IndexOf((byte)0);
                if (valueLength < 0)
                    break;

                var name = Encoding.UTF8.GetString(span.Slice(start, nameLength));
                var value = Encoding.UTF8.GetString(span.Slice(valueStart, valueLength));

                if (trailers)
                    message.TrailingHeaders.TryAddWithoutValidation(name, value);
                else if (!message.Headers.TryAddWithoutValidation(name, value))
                    message.Content.Headers.TryAddWithoutValidation(name, value);

                start = valueStart + valueLength + 1;
            }
        }

        static List<KeyValuePair<string, string>> DecodeInformationalHeaders(byte* data, int length)
        {
            var span = new ReadOnlySpan<byte>(data, length);
            var count = 0;
            foreach (var value in span)
            {
                if (value == 0)
                    count++;
            }
            var result = new List<KeyValuePair<string, string>>(count / 2);
            var start = 0;
            while (start < length)
            {
                var nameLength = span[start..].IndexOf((byte)0);
                if (nameLength < 0)
                    break;

                var valueStart = start + nameLength + 1;
                var valueLength = span[valueStart..].IndexOf((byte)0);
                if (valueLength < 0)
                    break;

                result.Add(
                    new KeyValuePair<string, string>(
                        Encoding.UTF8.GetString(span.Slice(start, nameLength)),
                        Encoding.UTF8.GetString(span.Slice(valueStart, valueLength))
                    )
                );
                start = valueStart + valueLength + 1;
            }
            return result;
        }
    }

    sealed class UploadStream : Stream
    {
        readonly RequestState state;

        internal UploadStream(RequestState state) => this.state = state;

        public override bool CanRead => false;
        public override bool CanSeek => false;
        public override bool CanWrite => true;
        public override long Length => throw new NotSupportedException();
        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override void Flush() { }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new NotSupportedException();

        public override long Seek(long offset, SeekOrigin origin) =>
            throw new NotSupportedException();

        public override void SetLength(long value) => throw new NotSupportedException();

        public override void Write(byte[] buffer, int offset, int count)
        {
            if (buffer == null)
                throw new ArgumentNullException(nameof(buffer));
            if ((uint)offset > (uint)buffer.Length)
                throw new ArgumentOutOfRangeException(nameof(offset));
            if ((uint)count > (uint)(buffer.Length - offset))
                throw new ArgumentOutOfRangeException(nameof(count));

            if (count == 0)
                return;

            if (!state.Write(buffer.AsSpan(offset, count)))
                throw new IOException("HTTP/3 request stream is closed.");
        }

        public override Task WriteAsync(
            byte[] buffer,
            int offset,
            int count,
            CancellationToken cancellationToken
        )
        {
            cancellationToken.ThrowIfCancellationRequested();
            Write(buffer, offset, count);
            return Task.CompletedTask;
        }

        public override ValueTask WriteAsync(
            ReadOnlyMemory<byte> buffer,
            CancellationToken cancellationToken = default
        )
        {
            cancellationToken.ThrowIfCancellationRequested();
            if (!state.Write(buffer.Span))
                throw new IOException("HTTP/3 request stream is closed.");
            return default;
        }
    }

    sealed class ResponseContent : HttpContent
    {
        readonly RequestState state;
        readonly PipeReader reader;

        internal ResponseContent(RequestState state, PipeReader reader)
        {
            this.state = state;
            this.reader = reader;
        }

        protected override bool TryComputeLength(out long length)
        {
            length = 0;
            return false;
        }

        protected override Task SerializeToStreamAsync(Stream stream, TransportContext? context) =>
            reader.CopyToAsync(stream);

#if NET8_0_OR_GREATER
        protected override Task SerializeToStreamAsync(
            Stream stream,
            TransportContext? context,
            CancellationToken cancellationToken
        ) => CopyResponseAsync(reader, stream, state, cancellationToken);
#endif

        protected override Task<Stream> CreateContentReadStreamAsync() =>
            Task.FromResult(reader.AsStream());

        protected override void Dispose(bool disposing)
        {
            if (disposing)
                state.Abandon();
            base.Dispose(disposing);
        }
    }
}
