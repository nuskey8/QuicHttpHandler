using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Net.Http;
using System.Threading;

namespace Nuskey.Net.Quic;

/// <summary>Names used by the handler's OpenTelemetry-compatible diagnostics.</summary>
public static class QuicHttpHandlerDiagnostics
{
    static readonly ConcurrentDictionary<long, WeakReference<QuicHttpHandler>> Handlers = new();
    static long nextHandlerId;

    public const string ActivitySourceName = "Nuskey.Net.Quic.QuicHttpHandler";
    public const string MeterName = ActivitySourceName;

    internal static readonly ActivitySource ActivitySource = new(ActivitySourceName);
    internal static readonly Meter Meter = new(MeterName);
    internal static readonly Counter<long> Requests = Meter.CreateCounter<long>(
        "quic.http.client.requests",
        "{request}"
    );
    internal static readonly Counter<long> Failures = Meter.CreateCounter<long>(
        "quic.http.client.failures",
        "{request}"
    );
    internal static readonly UpDownCounter<long> ActiveRequests = Meter.CreateUpDownCounter<long>(
        "quic.http.client.active_requests",
        "{request}"
    );
    internal static readonly Histogram<double> Duration = Meter.CreateHistogram<double>(
        "quic.http.client.request.duration",
        "ms"
    );
    static readonly ObservableGauge<long> Connections = Meter.CreateObservableGauge(
        "quic.http.client.connections",
        () => Observe(static statistics => statistics.Connections),
        "{connection}"
    );
    static readonly ObservableGauge<long> AcceptingConnections = Meter.CreateObservableGauge(
        "quic.http.client.connections.accepting",
        () => Observe(static statistics => statistics.AcceptingConnections),
        "{connection}"
    );
    static readonly ObservableGauge<long> IdleConnections = Meter.CreateObservableGauge(
        "quic.http.client.connections.idle",
        () => Observe(static statistics => statistics.IdleConnections),
        "{connection}"
    );
    static readonly ObservableGauge<long> PoolRequests = Meter.CreateObservableGauge(
        "quic.http.client.pool.requests",
        () => Observe(static statistics => checked((long)statistics.TotalRequests)),
        "{request}"
    );
    static readonly ObservableGauge<long> EarlyDataAttempts = Meter.CreateObservableGauge(
        "quic.http.client.early_data.attempts",
        () => Observe(static statistics => checked((long)statistics.EarlyDataAttempts)),
        "{request}"
    );
    static readonly ObservableGauge<long> EarlyDataAccepted = Meter.CreateObservableGauge(
        "quic.http.client.early_data.accepted",
        () => Observe(static statistics => checked((long)statistics.EarlyDataAccepted)),
        "{request}"
    );
    static readonly ObservableGauge<long> EarlyDataRejected = Meter.CreateObservableGauge(
        "quic.http.client.early_data.rejected",
        () => Observe(static statistics => checked((long)statistics.EarlyDataRejected)),
        "{request}"
    );

    internal static void Register(QuicHttpHandler handler)
    {
        Handlers.TryAdd(
            Interlocked.Increment(ref nextHandlerId),
            new WeakReference<QuicHttpHandler>(handler)
        );
    }

    static long Observe(Func<ConnectionPoolStatistics, long> select)
    {
        long total = 0;
        foreach (var entry in Handlers)
        {
            if (!entry.Value.TryGetTarget(out var handler))
            {
                Handlers.TryRemove(entry.Key, out _);
                continue;
            }

            total = checked(total + select(handler.GetConnectionPoolStatisticsForDiagnostics()));
        }
        return total;
    }

    internal static Activity? Start(HttpRequestMessage request)
    {
        if (!ActivitySource.HasListeners())
            return null;
        var activity = ActivitySource.StartActivity(
            "HTTP " + request.Method.Method,
            ActivityKind.Client
        );
        if (activity == null)
            return null;
        activity.SetTag("http.request.method", request.Method.Method);
        activity.SetTag("network.protocol.name", "http");
        activity.SetTag("network.protocol.version", "3");
        activity.SetTag("server.address", request.RequestUri!.IdnHost);
        activity.SetTag("server.port", request.RequestUri.Port);
        activity.SetTag("url.scheme", "https");
        return activity;
    }
}
