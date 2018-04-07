using System;
using System.Runtime.CompilerServices;
using System.Threading;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    internal static class Sodium
    {
        private static readonly Action s_misuseHandler = new Action(InternalError);

        private static int s_initialized;

        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void Initialize()
        {
            if (s_initialized == 0)
            {
                InitializeCore();
                Interlocked.Exchange(ref s_initialized, 1);
            }
        }

        [MethodImpl(MethodImplOptions.NoInlining)]
        private static void InitializeCore()
        {
            try
            {
                if (sodium_library_version_major() != SODIUM_LIBRARY_VERSION_MAJOR ||
                    sodium_library_version_minor() != SODIUM_LIBRARY_VERSION_MINOR)
                {
                    throw Error.Cryptographic_InitializationFailed();
                }

                if (sodium_set_misuse_handler(s_misuseHandler) != 0)
                {
                    throw Error.Cryptographic_InitializationFailed();
                }

                // sodium_init() returns 0 on success, -1 on failure, and 1 if the
                // library had already been initialized.

                if (sodium_init() < 0)
                {
                    throw Error.Cryptographic_InitializationFailed();
                }
            }
            catch (DllNotFoundException e)
            {
                throw Error.PlatformNotSupported_Initialization(e);
            }
            catch (BadImageFormatException e)
            {
                throw Error.PlatformNotSupported_Initialization(e);
            }
        }

        private static void InternalError()
        {
            throw Error.Cryptographic_InternalError();
        }
    }
}
