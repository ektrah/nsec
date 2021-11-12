using System;
using System.Diagnostics;
using System.Threading;
using NSec.Cryptography;
using static Interop.Libsodium;

namespace NSec.Experimental
{
    // Stream cipher encryption/decryption algorithm without any authentication.
    // This is not usually recommended for any communication protocol and should
    // be used only as a building block for a more high level protocol.
    public abstract class StreamCipherAlgorithm : Algorithm
    {
        private static ChaCha20? s_ChaCha20;

        private readonly int _keySize;
        private readonly int _nonceSize;

        private protected StreamCipherAlgorithm(
            int keySize,
            int nonceSize)
        {
            Debug.Assert(keySize > 0);
            Debug.Assert(nonceSize >= 0 && nonceSize <= 24);

            _keySize = keySize;
            _nonceSize = nonceSize;
        }

        public static ChaCha20 ChaCha20
        {
            get
            {
                ChaCha20? instance = s_ChaCha20;
                if (instance == null)
                {
                    Interlocked.CompareExchange(ref s_ChaCha20, new ChaCha20(), null);
                    instance = s_ChaCha20;
                }
                return instance;
            }
        }

        public int KeySize => _keySize;

        public int NonceSize => _nonceSize;

        [Obsolete("The 'Nonce' type has been deprecated. Pass the nonce as 'ReadOnlySpan<byte>' instead.")]
        public byte[] GeneratePseudoRandomStream(
            Key key,
            in Nonce nonce,
            int count)
        {
            if (key == null)
            {
                throw Error.ArgumentNull_Key(nameof(key));
            }
            if (key.Algorithm != this)
            {
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            }
            if (nonce.Size != _nonceSize)
            {
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            }
            if (count < 0)
            {
                throw Error.ArgumentOutOfRange_GenerateNegativeCount(nameof(count));
            }

            Span<byte> n = stackalloc byte[_nonceSize];
            nonce.CopyTo(n);

            byte[] bytes = new byte[count];
            GeneratePseudoRandomStreamCore(key.Handle, n, bytes);
            return bytes;
        }

        [Obsolete("The 'Nonce' type has been deprecated. Pass the nonce as 'ReadOnlySpan<byte>' instead.")]
        public void GeneratePseudoRandomStream(
            Key key,
            in Nonce nonce,
            Span<byte> bytes)
        {
            if (key == null)
            {
                throw Error.ArgumentNull_Key(nameof(key));
            }
            if (key.Algorithm != this)
            {
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            }
            if (nonce.Size != _nonceSize)
            {
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            }

            Span<byte> n = stackalloc byte[_nonceSize];
            nonce.CopyTo(n);

            GeneratePseudoRandomStreamCore(key.Handle, n, bytes);
        }

        public byte[] GeneratePseudoRandomStream(
            Key key,
            ReadOnlySpan<byte> nonce,
            int count)
        {
            if (key == null)
            {
                throw Error.ArgumentNull_Key(nameof(key));
            }
            if (key.Algorithm != this)
            {
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            }
            if (nonce.Length != _nonceSize)
            {
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            }
            if (count < 0)
            {
                throw Error.ArgumentOutOfRange_GenerateNegativeCount(nameof(count));
            }

            byte[] bytes = new byte[count];
            GeneratePseudoRandomStreamCore(key.Handle, nonce, bytes);
            return bytes;
        }

        public void GeneratePseudoRandomStream(
            Key key,
            ReadOnlySpan<byte> nonce,
            Span<byte> bytes)
        {
            if (key == null)
            {
                throw Error.ArgumentNull_Key(nameof(key));
            }
            if (key.Algorithm != this)
            {
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            }
            if (nonce.Length != _nonceSize)
            {
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            }

            GeneratePseudoRandomStreamCore(key.Handle, nonce, bytes);
        }

        [Obsolete("The 'Nonce' type has been deprecated. Pass the nonce as 'ReadOnlySpan<byte>' instead.")]
        public byte[] XOr(
            Key key,
            in Nonce nonce,
            ReadOnlySpan<byte> input)
        {
            if (key == null)
            {
                throw Error.ArgumentNull_Key(nameof(key));
            }
            if (key.Algorithm != this)
            {
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            }
            if (nonce.Size != _nonceSize)
            {
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            }

            Span<byte> n = stackalloc byte[_nonceSize];
            nonce.CopyTo(n);

            byte[] output = new byte[input.Length];
            XOrCore(key.Handle, n, input, output);
            return output;
        }

        [Obsolete("The 'Nonce' type has been deprecated. Pass the nonce as 'ReadOnlySpan<byte>' instead.")]
        public void XOr(
            Key key,
            in Nonce nonce,
            ReadOnlySpan<byte> input,
            Span<byte> output)
        {
            if (key == null)
            {
                throw Error.ArgumentNull_Key(nameof(key));
            }
            if (key.Algorithm != this)
            {
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            }
            if (nonce.Size != _nonceSize)
            {
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            }
            if (output.Length != input.Length)
            {
                throw Error.Argument_CiphertextLength(nameof(output)); // TODO
            }
            if (output.Overlaps(input, out int offset) && offset != 0)
            {
                throw Error.Argument_OverlapCiphertext(nameof(output)); // TODO
            }

            Span<byte> n = stackalloc byte[_nonceSize];
            nonce.CopyTo(n);

            XOrCore(key.Handle, n, input, output);
        }

        public byte[] XOr(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> input)
        {
            if (key == null)
            {
                throw Error.ArgumentNull_Key(nameof(key));
            }
            if (key.Algorithm != this)
            {
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            }
            if (nonce.Length != _nonceSize)
            {
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            }

            byte[] output = new byte[input.Length];
            XOrCore(key.Handle, nonce, input, output);
            return output;
        }

        public void XOr(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> input,
            Span<byte> output)
        {
            if (key == null)
            {
                throw Error.ArgumentNull_Key(nameof(key));
            }
            if (key.Algorithm != this)
            {
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            }
            if (nonce.Length != _nonceSize)
            {
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            }
            if (output.Length != input.Length)
            {
                throw Error.Argument_CiphertextLength(nameof(output)); // TODO
            }
            if (output.Overlaps(input, out int offset) && offset != 0)
            {
                throw Error.Argument_OverlapCiphertext(nameof(output)); // TODO
            }

            XOrCore(key.Handle, nonce, input, output);
        }

        [Obsolete("The 'Nonce' type has been deprecated. Pass the nonce as 'ReadOnlySpan<byte>' instead.")]
        public byte[] XOrIC(
            Key key,
            in Nonce nonce,
            ReadOnlySpan<byte> input,
            uint ic)
        {
            if (key == null)
            {
                throw Error.ArgumentNull_Key(nameof(key));
            }
            if (key.Algorithm != this)
            {
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            }
            if (nonce.Size != _nonceSize)
            {
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            }

            Span<byte> n = stackalloc byte[_nonceSize];
            nonce.CopyTo(n);

            byte[] output = new byte[input.Length];
            XOrICCore(key.Handle, n, input, ic, output);
            return output;
        }

        [Obsolete("The 'Nonce' type has been deprecated. Pass the nonce as 'ReadOnlySpan<byte>' instead.")]
        public void XOrIC(
            Key key,
            in Nonce nonce,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            uint ic)
        {
            if (key == null)
            {
                throw Error.ArgumentNull_Key(nameof(key));
            }
            if (key.Algorithm != this)
            {
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            }
            if (nonce.Size != _nonceSize)
            {
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            }
            if (output.Length != input.Length)
            {
                throw Error.Argument_CiphertextLength(nameof(output)); // TODO
            }
            if (output.Overlaps(input, out int offset) && offset != 0)
            {
                throw Error.Argument_OverlapCiphertext(nameof(output)); // TODO
            }

            Span<byte> n = stackalloc byte[_nonceSize];
            nonce.CopyTo(n);

            XOrICCore(key.Handle, n, input, ic, output);
        }

        public byte[] XOrIC(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> input,
            uint ic)
        {
            if (key == null)
            {
                throw Error.ArgumentNull_Key(nameof(key));
            }
            if (key.Algorithm != this)
            {
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            }
            if (nonce.Length != _nonceSize)
            {
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            }

            byte[] output = new byte[input.Length];
            XOrICCore(key.Handle, nonce, input, ic, output);
            return output;
        }

        public void XOrIC(
            Key key,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> input,
            Span<byte> output,
            uint ic)
        {
            if (key == null)
            {
                throw Error.ArgumentNull_Key(nameof(key));
            }
            if (key.Algorithm != this)
            {
                throw Error.Argument_KeyAlgorithmMismatch(nameof(key), nameof(key));
            }
            if (nonce.Length != _nonceSize)
            {
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            }
            if (output.Length != input.Length)
            {
                throw Error.Argument_CiphertextLength(nameof(output)); // TODO
            }
            if (output.Overlaps(input, out int offset) && offset != 0)
            {
                throw Error.Argument_OverlapCiphertext(nameof(output)); // TODO
            }

            XOrICCore(key.Handle, nonce, input, ic, output);
        }

        internal sealed override int GetKeySize()
        {
            return _keySize;
        }

        internal sealed override int GetPublicKeySize()
        {
            throw Error.InvalidOperation_InternalError();
        }

        internal abstract override int GetSeedSize();

        private protected abstract void GeneratePseudoRandomStreamCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            Span<byte> bytes);

        private protected abstract void XOrCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> input,
            Span<byte> output);

        private protected abstract void XOrICCore(
            SecureMemoryHandle keyHandle,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> input,
            uint ic,
            Span<byte> output);
    }
}
