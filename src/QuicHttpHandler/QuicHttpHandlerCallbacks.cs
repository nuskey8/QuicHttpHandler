using System;
using System.Collections.Generic;
using System.Net.Http;

namespace Nuskey.Net.Quic;

public delegate bool ServerCertificateVerificationHandler(
    ServerCertificateVerificationContext context
);

/// <summary>Receives allocation-free UTF-8 qlog data valid only for the duration of the call.</summary>
public delegate void QlogEventHandler(
    ReadOnlySpan<byte> connectionIdUtf8,
    ReadOnlySpan<byte> jsonUtf8
);

public delegate void InformationalResponseHandler(
    HttpRequestMessage request,
    uint statusCode,
    IReadOnlyList<KeyValuePair<string, string>> headers
);
