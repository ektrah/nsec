using System;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    internal static class Sodium
    {
        private static readonly Lazy<int> s_initialized = new Lazy<int>(new Func<int>(sodium_init));
        private static readonly Lazy<int> s_versionMajor = new Lazy<int>(new Func<int>(sodium_library_version_major));
        private static readonly Lazy<int> s_versionMinor = new Lazy<int>(new Func<int>(sodium_library_version_minor));

        public static bool TryInitialize()
        {
            // require libsodium 1.0.4 or later
            if ((s_versionMajor.Value < 7) || (s_versionMajor.Value == 7 && s_versionMinor.Value < 6))
            {
                return false;
            }

            return (s_initialized.Value == 0);
        }
    }
}
