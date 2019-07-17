using System;
using System.Diagnostics;
using System.Threading;

namespace NSec.Cryptography
{

    // stream cipher encryption/decryption algorithm without any authentication.
    // This is not usually recommended for any communication protocol.
    // And should be used only as a building block for more high level protocol.
    public abstract class StreamCipherAlgorithm: Algorithm
    {

        private static ChaCha20 s_ChaCha20;

        private readonly int _keySize;
        private readonly int _nonceSize;

        private protected StreamCipherAlgorithm(
            int keySize,
            int nonceSize
        )
        {
            Debug.Assert(keySize > 0);
            Debug.Assert(nonceSize >= 0 && nonceSize <= Nonce.MaxSize);
            _keySize = keySize;
            _nonceSize = nonceSize;
        }

        public static ChaCha20 ChaCha20
        {
            get
            {
                ChaCha20 instance = s_ChaCha20;
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

        public byte[] GeneratePseudoRandomStream(
            Key key,
            in Nonce nonce,
            int length)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            if (length > int.MaxValue)
                throw Error.Argument_CiphertextLength(nameof(length));

            byte[] stream = new byte[length];
            GeneratePseudoRandomStreamCore(key.Span, nonce, stream);
            return stream;
        }

        public void GeneratePseudoRandomStream(
            Key key,
            in Nonce nonce,
            Span<byte> randomStream
        )
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            if (randomStream.Length > int.MaxValue)
                throw Error.Argument_CiphertextLength(nameof(randomStream));

            GeneratePseudoRandomStreamCore(key.Span, nonce, randomStream);
        }

        public byte[] XOr(
            Key key,
            in Nonce nonce,
            ReadOnlySpan<byte> inputText
        )
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            if (inputText.Length > int.MaxValue)
                throw Error.Argument_PlaintextTooLong(nameof(inputText), int.MaxValue);

            byte[] ciphertext = new byte[inputText.Length];
            XOrCore(key.Span, in nonce, inputText, ciphertext);
            return ciphertext;

        }
        public void XOr(
            Key key,
            in Nonce nonce,
            ReadOnlySpan<byte> inputText,
            Span<byte> outputText)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            if (outputText.Length != inputText.Length)
                throw Error.Argument_CiphertextLength(nameof(outputText));
            if (outputText.Overlaps(inputText, out int offset) && offset != 0)
                throw Error.Argument_OverlapCiphertext(nameof(outputText));

            XOrCore(key.Span, in nonce, inputText, outputText);
        }

        public void XOrIC(
            Key key,
            in Nonce nonce,
            ReadOnlySpan<byte> inputText,
            Span<byte> outputText,
            uint ic)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);
            if (outputText.Length != inputText.Length)
                throw Error.Argument_CiphertextLength(nameof(outputText));
            if (outputText.Overlaps(inputText, out int offset) && offset != 0)
                throw Error.Argument_OverlapCiphertext(nameof(outputText));

            XOrICCore(key.Span, in nonce, inputText, ic, outputText);
        }

        public byte[] XOrIC(
            Key key,
            in Nonce nonce,
            ReadOnlySpan<byte> inputText,
            uint ic)
        {
            if (key == null)
                throw Error.ArgumentNull_Key(nameof(key));
            if (key.Algorithm != this)
                throw Error.Argument_KeyWrongAlgorithm(nameof(key), key.Algorithm.GetType().FullName, GetType().FullName);
            if (nonce.Size != _nonceSize)
                throw Error.Argument_NonceLength(nameof(nonce), _nonceSize);

            byte[] outputText = new byte[inputText.Length];
            XOrICCore(key.Span, in nonce, inputText, ic, outputText);
            return outputText;
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
            ReadOnlySpan<byte> key,
            in Nonce nonce,
            Span<byte> stream
        );

        private protected abstract void XOrCore(
            ReadOnlySpan<byte> key,
            in Nonce nonce,
            ReadOnlySpan<byte> plaintext,
            Span<byte> ciphertext);

        private protected abstract void XOrICCore(
            ReadOnlySpan<byte> key,
            in Nonce nonce,
            ReadOnlySpan<byte> plaintext,
            uint ic,
            Span<byte> ciphertext);
    }
}
