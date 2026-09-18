namespace Nuskey.Net.Quic;

internal enum NativeCompletionCode
{
    Success = 0,
    Failure = 1,
    Cancelled = 3,
    ConnectionDraining = 4,
    ConnectionFailureBeforeHeaders = 5,
    RequestRejected = 6,
}

internal enum NativeErrorKind
{
    Local = 0,
    QuicTransport = 1,
    Http3Application = 2,
    TlsHandshake = 4,
}
