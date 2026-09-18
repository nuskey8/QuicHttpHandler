using System;
using System.Threading;

namespace Nuskey.Net.Quic;

internal static class Guard
{
    public static void Positive(int value, string name)
    {
        if (value <= 0)
            throw new ArgumentOutOfRangeException(name);
    }

    public static void Positive(long value, string name)
    {
        if (value <= 0)
            throw new ArgumentOutOfRangeException(name);
    }

    public static void NonNegative(int value, string name)
    {
        if (value < 0)
            throw new ArgumentOutOfRangeException(name);
    }

    public static void NonNegative(long value, string name)
    {
        if (value < 0)
            throw new ArgumentOutOfRangeException(name);
    }

    public static void PositiveTimeout(TimeSpan value, string name)
    {
        if (value <= TimeSpan.Zero || value == Timeout.InfiniteTimeSpan)
            throw new ArgumentOutOfRangeException(name);
    }

    public static void NonNegativeTimeout(TimeSpan value, string name)
    {
        if (value < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(name);
    }

    public static void NonNegativeOrInfiniteTimeout(TimeSpan value, string name)
    {
        if (value < TimeSpan.Zero && value != Timeout.InfiniteTimeSpan)
            throw new ArgumentOutOfRangeException(name);
    }

    public static void PositiveOrInfiniteTimeout(TimeSpan value, string name)
    {
        if (value != Timeout.InfiniteTimeSpan && value <= TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(name);
    }

    public static void NotNull<T>(T? value, string name)
        where T : class
    {
        if (value == null)
            throw new ArgumentNullException(name);
    }

    public static void QuicTransport(QuicTransportOptions options)
    {
        if (
            options.InitialMaxData <= 0
            || options.InitialMaxStreamDataBidirectionalLocal <= 0
            || options.InitialMaxStreamDataBidirectionalRemote <= 0
            || options.InitialMaxStreamDataUnidirectional <= 0
            || options.InitialMaxStreamsBidirectional <= 0
            || options.InitialMaxStreamsUnidirectional <= 0
            || options.MaxConnectionWindow <= 0
            || options.MaxStreamWindow <= 0
            || options.SendBufferSize < 0
            || options.ReceiveBufferSize < 0
            || options.InitialCongestionWindowPackets <= 0
            || options.PmtudMaxProbes == 0
            || options.MaxSendUdpPayloadSize < 1200
            || options.MaxReceiveUdpPayloadSize < 1200
            || options.AckDelayExponent > 20
            || options.MaxAckDelay < TimeSpan.Zero
            || double.IsNaN(options.SendCapacityFactor)
            || double.IsInfinity(options.SendCapacityFactor)
            || options.SendCapacityFactor <= 0
        )
            throw new InvalidOperationException("Invalid QUIC transport configuration.");
    }

    public static void QuicFlowControl(
        long initialMaxData,
        long initialMaxStreamDataBidirectionalLocal,
        long initialMaxStreamDataBidirectionalRemote,
        long initialMaxStreamDataUnidirectional,
        long maxConnectionWindow,
        long maxStreamWindow
    )
    {
        if (
            maxConnectionWindow < initialMaxData
            || maxStreamWindow
                < Math.Max(
                    initialMaxStreamDataBidirectionalLocal,
                    Math.Max(
                        initialMaxStreamDataBidirectionalRemote,
                        initialMaxStreamDataUnidirectional
                    )
                )
        )
            throw new InvalidOperationException(
                "QUIC flow-control windows cannot be smaller than their initial limits."
            );
    }
}
