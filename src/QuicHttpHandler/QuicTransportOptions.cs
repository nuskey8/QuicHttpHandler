using System;

namespace Nuskey.Net.Quic;

public enum QuicCongestionControlAlgorithm : byte
{
    Cubic,
    Reno,
    Bbr2,
}

public sealed record QuicTransportOptions
{
    public static readonly QuicTransportOptions Default = new();

    public QuicCongestionControlAlgorithm CongestionControlAlgorithm { get; init; } =
        QuicCongestionControlAlgorithm.Cubic;
    public long InitialMaxData { get; init; } = 10 * 1024 * 1024;
    public long InitialMaxStreamDataBidirectionalLocal { get; init; } = 1024 * 1024;
    public long InitialMaxStreamDataBidirectionalRemote { get; init; } = 1024 * 1024;
    public long InitialMaxStreamDataUnidirectional { get; init; } = 1024 * 1024;
    public long InitialMaxStreamsBidirectional { get; init; } = 100;
    public long InitialMaxStreamsUnidirectional { get; init; } = 100;
    public long MaxConnectionWindow { get; init; } = 24 * 1024 * 1024;
    public long MaxStreamWindow { get; init; } = 16 * 1024 * 1024;
    public int SendBufferSize { get; init; }
    public int ReceiveBufferSize { get; init; }
    public int InitialCongestionWindowPackets { get; init; } = 10;
    public bool EnablePacing { get; init; }
    public ulong? MaxPacingRate { get; init; }
    public bool DiscoverPathMtu { get; init; }
    public byte PmtudMaxProbes { get; init; } = 3;
    public bool EnableHyStart { get; init; } = true;
    public int MaxSendUdpPayloadSize { get; init; } = 1350;
    public int MaxReceiveUdpPayloadSize { get; init; } = 1350;
    public byte AckDelayExponent { get; init; } = 3;
    public TimeSpan MaxAckDelay { get; init; } = TimeSpan.FromMilliseconds(25);
    public double SendCapacityFactor { get; init; } = 1.0;
}
