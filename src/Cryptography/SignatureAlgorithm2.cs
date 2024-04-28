using System;
using static Interop.Libsodium;

namespace NSec.Cryptography
{
    //
    //  A digital signature algorithm supporting the "init, update, final" interface
    //
    //  Candidates
    //
    //      | Algorithm   | Reference  | Key Size | Signature Size |
    //      | ----------- | ---------- | -------- | -------------- |
    //      | Ed25519ph   | RFC 8032   | 32       | 64             |
    //      | Ed448ph     | RFC 8032   | 57       | 114            |
    //
    public abstract class SignatureAlgorithm2 : SignatureAlgorithm
    {
        private protected SignatureAlgorithm2(
            int privateKeySize,
            int publicKeySize,
            int signatureSize)
            : base(privateKeySize, publicKeySize, signatureSize)
        {
        }

        internal abstract void InitializeCore(
            out IncrementalSignatureState state);

        internal abstract void UpdateCore(
            ref IncrementalSignatureState state,
            ReadOnlySpan<byte> data);

        internal abstract void FinalSignCore(
            ref IncrementalSignatureState state,
            SecureMemoryHandle keyHandle,
            Span<byte> signature);

        internal abstract bool FinalVerifyCore(
            ref IncrementalSignatureState state,
            ref readonly PublicKeyBytes publicKeyBytes,
            ReadOnlySpan<byte> signature);
    }
}
