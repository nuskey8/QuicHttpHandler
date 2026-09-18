#if NET10_0_OR_GREATER
using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Nuskey.Net.Quic.Interop;

public static unsafe partial class NativeMethods
{
    static NativeMethods()
    {
        NativeLibrary.SetDllImportResolver(typeof(NativeMethods).Assembly, ResolveLibrary);
    }

    static IntPtr ResolveLibrary(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != "quic_http_handler")
            return IntPtr.Zero;

        var platform = RuntimeInformation.IsOSPlatform(OSPlatform.Windows) ? "win"
            : RuntimeInformation.IsOSPlatform(OSPlatform.OSX) ? "osx"
            : RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ? "linux"
            : null;
        var architecture = RuntimeInformation.ProcessArchitecture switch
        {
            Architecture.X64 => "x64",
            Architecture.Arm64 => "arm64",
            _ => null,
        };
        if (platform is null || architecture is null)
            return IntPtr.Zero;

        var fileName = platform == "win" ? "quic_http_handler.dll"
            : platform == "osx" ? "libquic_http_handler.dylib"
            : "libquic_http_handler.so";
        var path = Path.Combine(AppContext.BaseDirectory, "runtimes", $"{platform}-{architecture}", "native", fileName);

        if (NativeLibrary.TryLoad(path, out var handle))
            return handle;

        // NuGet copies runtime-specific native assets beside the application.
        NativeLibrary.TryLoad(libraryName, assembly, searchPath, out handle);
        return handle;
    }
}
#endif
