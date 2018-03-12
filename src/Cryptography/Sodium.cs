using System;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    internal static class Sodium
    {
        private static readonly Lazy<bool> s_initialized = new Lazy<bool>(new Func<bool>(InitializeCore));
        private static readonly Action s_misuseHandler = new Action(InternalError);

        public static void Initialize()
        {
            _ = s_initialized.Value;
        }

        public static bool IsAes256GcmSupported()
        {
            return s_initialized.Value;
        }

        private static bool InitializeCore()
        {
            try
            {
                if (sodium_library_version_major() != SODIUM_LIBRARY_VERSION_MAJOR ||
                    sodium_library_version_minor() != SODIUM_LIBRARY_VERSION_MINOR)
                {
                    throw Error.Cryptographic_InitializationFailed(9643.ToString("X"));
                }

                if (sodium_set_misuse_handler(s_misuseHandler) != 0)
                {
                    throw Error.Cryptographic_InitializationFailed(9739.ToString("X"));
                }

                // sodium_init() returns 0 on success, -1 on failure, and 1 if the
                // library had already been initialized. sodium_init() is called only
                // once due to the Lazy<T> wrapper, but if another library p/invokes
                // into libsodium it might have already been initialized.

                if (sodium_init() < 0)
                {
                    throw Error.Cryptographic_InitializationFailed(9817.ToString("X"));
                }

                return crypto_aead_aes256gcm_is_available() != 0;
            }
            catch (DllNotFoundException e)
            {
                throw Error.Cryptographic_DllNotFound(e);
            }
        }

        private static void InternalError()
        {
            throw Error.Cryptographic_InternalError();
        }
    }
}
