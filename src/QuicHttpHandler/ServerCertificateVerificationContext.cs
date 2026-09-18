using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace Nuskey.Net.Quic;

/// <summary>Certificate data is valid only for the duration of the verification callback.</summary>
public sealed class ServerCertificateVerificationContext
{
    internal ServerCertificateVerificationContext(
        string serverName,
        X509Certificate2 certificate,
        IReadOnlyList<X509Certificate2> certificateChain,
        DateTimeOffset verificationTime,
        bool standardVerificationSucceeded,
        int standardVerificationErrorCode
    )
    {
        ServerName = serverName;
        Certificate = certificate;
        CertificateChain = certificateChain;
        VerificationTime = verificationTime;
        StandardVerificationSucceeded = standardVerificationSucceeded;
        StandardVerificationErrorCode = standardVerificationErrorCode;
    }

    public string ServerName { get; }
    public X509Certificate2 Certificate { get; }
    public IReadOnlyList<X509Certificate2> CertificateChain { get; }
    public DateTimeOffset VerificationTime { get; }
    public bool StandardVerificationSucceeded { get; }
    public int StandardVerificationErrorCode { get; }
}
