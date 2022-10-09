#nullable enable
using System;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

#if NETSTANDARD2_0

namespace System.Runtime.CompilerServices
{
    [AttributeUsage(AttributeTargets.Method)]
    public sealed class ModuleInitializerAttribute : Attribute
    {
    }
}

internal static class NsecModuleInitializer
{
    [ModuleInitializer]
    internal static void Init()
    {
        if (!(RuntimeInformation.IsOSPlatform(OSPlatform.Windows)
            && RuntimeInformation.FrameworkDescription.StartsWith(".NET Framework")))
        {
            return;
        }

        var path = Path.GetDirectoryName(new Uri(Assembly.GetExecutingAssembly().CodeBase).LocalPath);

        if (!File.Exists(Path.Combine(path, "libsodium.dll")))
        {
            path = IntPtr.Size == 8
                ? Path.Combine(path, "runtimes", "win-x64", "native")
                : Path.Combine(path, "runtimes", "win-x86", "native");
        }

        var dllPath = Path.Combine(path, "libsodium.dll");
        if (File.Exists(dllPath))
        {
            LoadLibrary(dllPath);
        }

        [DllImport("Kernel32.dll")]
        static extern IntPtr LoadLibrary(string path);

    }
}

#endif
