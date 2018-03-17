using System.Runtime.InteropServices;

internal static partial class Interop
{
    internal static partial class Libsodium
    {
        [StructLayout(LayoutKind.Explicit, Size = 32)]
        internal readonly struct PublicKeyBytes
        {
        }
    }
}
