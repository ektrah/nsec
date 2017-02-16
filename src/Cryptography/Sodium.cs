using System;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  Libsodium Versions
    //
    //      | Version | Major | Minor |
    //      | ------- | ----- | ----- |
    //      | 1.0.11  |   9   |   3   |
    //      | 1.0.10  |   9   |   2   |
    //      | 1.0.9   |   9   |   2   |
    //      | 1.0.8   |   9   |   1   |
    //      | 1.0.7   |   9   |   0   |
    //      | 1.0.6   |   8   |   0   |
    //      | 1.0.5   |   7   |   6   |
    //      | 1.0.4   |   7   |   6   |
    //      | 1.0.3   |   7   |   5   |
    //      | 1.0.2   |   7   |   4   |
    //      | 1.0.1   |   7   |   3   |
    //      | 1.0.0   |   7   |   2   |
    //
    internal static class Sodium
    {
        private static readonly Lazy<int> s_initialized = new Lazy<int>(new Func<int>(sodium_init));
        private static readonly Lazy<int> s_versionMajor = new Lazy<int>(new Func<int>(sodium_library_version_major));
        private static readonly Lazy<int> s_versionMinor = new Lazy<int>(new Func<int>(sodium_library_version_minor));

        public static void Initialize()
        {
            if (!TryInitialize())
            {
                throw new InvalidOperationException();
            }
        }

        public static bool IsVersionOrLater(int major, int minor)
        {
            return (s_versionMajor.Value > major)
                || (s_versionMajor.Value == major && s_versionMinor.Value >= minor);
        }

        public static bool TryInitialize()
        {
            // Require libsodium 1.0.9 or later
            if (!IsVersionOrLater(9, 2))
            {
                return false;
            }

            // sodium_init() returns 0 on success, -1 on failure, and 1 if the
            // library had already been initialized. We call sodium_init() only
            // once, but if another library p/invokes into libsodium it might
            // already have been called.
            return (s_initialized.Value == 0) || (s_initialized.Value == 1);
        }
    }
}
