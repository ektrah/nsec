using System;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    internal static class Sodium
    {
        private static readonly Lazy<int> s_initialized = new Lazy<int>(new Func<int>(sodium_init));

        public static bool TryInitialize()
        {
            return (s_initialized.Value == 0);
        }
    }
}
