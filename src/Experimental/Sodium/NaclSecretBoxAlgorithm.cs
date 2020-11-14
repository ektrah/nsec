using System;
using System.Diagnostics;
using NSec.Cryptography;
using static Interop.Libsodium;

namespace NSec.Experimental.Sodium
{
    public abstract class NaclSecretBoxAlgorithm : Algorithm
    {
        private readonly int _keySize;
        private readonly int _macSize;
        private readonly int _nonceSize;

        private protected NaclSecretBoxAlgorithm(
            int keySize,
            int nonceSize,
            int macSize)
        {
            Debug.Assert(keySize > 0);
            Debug.Assert(nonceSize >= 0 && nonceSize <= 24);
            Debug.Assert(macSize >= 0);

            _keySize = keySize;
            _nonceSize = nonceSize;
            _macSize = macSize;
        }

        public int KeySize => _keySize;

        public int MacSize => _macSize;

        public int NonceSize => _nonceSize;

        [Obsolete("The 'Nonce' type has been deprecated. Pass the nonce as 'ReadOnlySpan<byte>' instead.")]
        public byte[] Encrypt(
            Key key,
            in Nonce nonce,
            ReadOnlySpan<byte> plaintext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            if (plaintext.Length > int.MaxValue - _macSize)
                throw Error.Argument_PlaintextTooLong(nameof(plaintext), int.MaxValue - _macSize);

            Span<byte> n = stackalloc byte[_nonceSize];
            nonce.CopyTo(n);

            byte[] ciphertext = new byte[_macSize + plaintext.Length];
            EncryptCore(key.Handle, n, plaintext, ciphertext);
            return ciphertext;
        }

        [Obsolete("The 'Nonce' type has been deprecated. Pass the nonce as 'ReadOnlySpan<byte>' instead.")]
        public void Encrypt(
            Key key,
            in Nonce nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            if (plaintext.Length > int.MaxValue - _macSize)
                throw Error.Argument_PlaintextTooLong(nameof(plaintext), int.MaxValue - _macSize);
            if (ciphertext.Length != _macSize + plaintext.Length)
                throw Error.Argument_CiphertextLength(nameof(ciphertext));
            if (ciphertext.Overlaps(plaintext))
                throw Error.Argument_OverlapCiphertext(nameof(ciphertext));

            Span<byte> n = stackalloc byte[_nonceSize];
            nonce.CopyTo(n);

            EncryptCore(key.Handle, n, plaintext, ciphertext);
        }

        public byte[] Encrypt(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            if (nonce.Length != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            if (plaintext.Length > int.MaxValue - _macSize)
                throw Error.Argument_PlaintextTooLong(nameof(plaintext), int.MaxValue - _macSize);

            byte[] ciphertext = new byte[_macSize + plaintext.Length];
            EncryptCore(key.Handle, nonce, plaintext, ciphertext);
            return ciphertext;
        }

        public void Encrypt(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            if (nonce.Length != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            if (plaintext.Length > int.MaxValue - _macSize)
                throw Error.Argument_PlaintextTooLong(nameof(plaintext), int.MaxValue - _macSize);
            if (ciphertext.Length != _macSize + plaintext.Length)
                throw Error.Argument_CiphertextLength(nameof(ciphertext));
            if (ciphertext.Overlaps(plaintext))
                throw Error.Argument_OverlapCiphertext(nameof(ciphertext));

            EncryptCore(key.Handle, nonce, plaintext, ciphertext);
        }

        [Obsolete("The 'Nonce' type has been deprecated. Pass the nonce as 'ReadOnlySpan<byte>' instead.")]
        public bool Decrypt(
            Key key,
            in Nonce nonce,
            ReadOnlySpan<byte> ciphertext,
            out byte[]? plaintext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);

            if (ciphertext.Length < _macSize)
            {
                plaintext = null;
                return false;
            }

            Span<byte> n = stackalloc byte[_nonceSize];
            nonce.CopyTo(n);

            byte[] result = new byte[ciphertext.Length - _macSize];
            bool success = DecryptCore(key.Handle, n, ciphertext, result);
            plaintext = success ? result : null;
            return success;
        }

        [Obsolete("The 'Nonce' type has been deprecated. Pass the nonce as 'ReadOnlySpan<byte>' instead.")]
        public bool Decrypt(
            Key key,
            in Nonce nonce,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            if (ciphertext.Length < _macSize)
                return false;
            if (plaintext.Length != ciphertext.Length - _macSize)
                throw Error.Argument_PlaintextLength(nameof(plaintext));
            if (plaintext.Overlaps(ciphertext))
                throw Error.Argument_OverlapPlaintext(nameof(plaintext));

            Span<byte> n = stackalloc byte[_nonceSize];
            nonce.CopyTo(n);

            return DecryptCore(key.Handle, n, ciphertext, plaintext);
        }

        public bool Decrypt(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            out byte[]? plaintext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            if (nonce.Length != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);

            if (ciphertext.Length < _macSize)
            {
                plaintext = null;
                return false;
            }

            byte[] result = new byte[ciphertext.Length - _macSize];
            bool success = DecryptCore(key.Handle, nonce, ciphertext, result);
            plaintext = success ? result : null;
            return success;
        }

        public bool Decrypt(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            if (nonce.Length != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            if (ciphertext.Length < _macSize)
                return false;
            if (plaintext.Length != ciphertext.Length - _macSize)
                throw Error.Argument_PlaintextLength(nameof(plaintext));
            if (plaintext.Overlaps(ciphertext))
                throw Error.Argument_OverlapPlaintext(nameof(plaintext));

            return DecryptCore(key.Handle, nonce, ciphertext, plaintext);
        }

        internal abstract void EncryptCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext);

        internal sealed override int GetKeySize()
        {
            return _keySize;
        }

        internal sealed override int GetPublicKeySize()
        {
            throw Error.InvalidOperation_InternalError();
        }

        internal abstract override int GetSeedSize();

        internal abstract bool DecryptCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext,
            Span<byte> plaintext);
    }
}
