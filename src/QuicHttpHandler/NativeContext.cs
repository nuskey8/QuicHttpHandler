using System;
using System.Runtime.InteropServices;
using Nuskey.Net.Quic.Interop;

namespace Nuskey.Net.Quic;

internal sealed unsafe class NativeContext : IDisposable
{
    Context* context;
    GCHandle callbackHandle;

    internal NativeContext(
        QuicHttpHandler owner,
        int workerThreads,
        NativeMethods.qhh_context_new_on_headers_delegate onHeaders,
        NativeMethods.qhh_context_new_on_body_delegate onBody,
        NativeMethods.qhh_context_new_on_trailers_delegate onTrailers,
        NativeMethods.qhh_context_new_on_informational_headers_delegate onInformationalHeaders,
        NativeMethods.qhh_context_new_on_complete_delegate onComplete
    )
    {
        context = NativeMethods.qhh_context_new(
            workerThreads,
            onHeaders,
            onBody,
            onTrailers,
            onInformationalHeaders,
            onComplete
        );
        if (context == null)
            throw new InvalidOperationException("Failed to initialize the native HTTP/3 runtime.");

        try
        {
            callbackHandle = GCHandle.Alloc(owner);
            owner.ConfigureNativeContext(context, (void*)GCHandle.ToIntPtr(callbackHandle));
        }
        catch
        {
            Dispose();
            throw;
        }
    }

    internal Context* Context =>
        context == null ? throw new ObjectDisposedException(nameof(NativeContext)) : context;

    internal ConnectionPoolStatistics GetPoolStatistics()
    {
        nuint connections;
        nuint acceptingConnections;
        nuint idleConnections;
        nuint activeRequests;
        ulong totalRequests;
        ulong earlyDataAttempts;
        ulong earlyDataAccepted;
        ulong earlyDataRejected;
        if (
            !NativeMethods.qhh_context_get_pool_statistics(
                Context,
                &connections,
                &acceptingConnections,
                &idleConnections,
                &activeRequests,
                &totalRequests,
                &earlyDataAttempts,
                &earlyDataAccepted,
                &earlyDataRejected
            )
        )
            throw new InvalidOperationException("Failed to read native connection statistics.");

        return new ConnectionPoolStatistics(
            checked((int)connections),
            checked((int)acceptingConnections),
            checked((int)idleConnections),
            totalRequests,
            earlyDataAttempts,
            earlyDataAccepted,
            earlyDataRejected
        );
    }

    public void Dispose()
    {
        var nativeContext = context;
        context = null;

        if (nativeContext != null)
            NativeMethods.qhh_context_dispose(nativeContext);

        if (callbackHandle.IsAllocated)
            callbackHandle.Free();
    }
}
