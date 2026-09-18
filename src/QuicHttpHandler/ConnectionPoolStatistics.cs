namespace Nuskey.Net.Quic;

internal readonly record struct ConnectionPoolStatistics(
    int Connections,
    int AcceptingConnections,
    int IdleConnections,
    ulong TotalRequests,
    ulong EarlyDataAttempts,
    ulong EarlyDataAccepted,
    ulong EarlyDataRejected
);
