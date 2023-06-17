namespace NSec.Cryptography
{
    using System.Runtime.InteropServices;

    [StructLayout(LayoutKind.Explicit)]
    internal struct IncrementalSignatureState
    {
        [FieldOffset(0)]
        internal Interop.Libsodium.crypto_sign_ed25519ph_state ed25519ph;
    }
}
