using System;
using NSec.Cryptography;

namespace NSec.Experimental.PasswordBased
{
    public static class PasswordBasedKeyExporter
    {
        public static byte[] Export(
            Key key,
            PasswordBasedEncryptionScheme scheme,
            string password,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> nonce)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            KeyBlobFormat format = SelectKeyBlobFormat(key.Algorithm);
            byte[] plaintext = key.Export(format);
            return Encrypt(plaintext, scheme, password, salt, nonce);
        }

        public static byte[] Export(
            Key key,
            PasswordBasedEncryptionScheme scheme,
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> nonce)
        {
            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            KeyBlobFormat format = SelectKeyBlobFormat(key.Algorithm);
            byte[] plaintext = key.Export(format);
            return Encrypt(plaintext, scheme, password, salt, nonce);
        }

        public static Key Import(
            Algorithm algorithm,
            ReadOnlySpan<byte> blob,
            PasswordBasedEncryptionScheme scheme,
            string password,
            in KeyCreationParameters creationParameters = default)
        {
            if (algorithm == null)
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            KeyBlobFormat format = SelectKeyBlobFormat(algorithm);
            byte[]? plaintext = Decrypt(blob, scheme, password);
            return Key.Import(algorithm, plaintext, format, in creationParameters);
        }

        public static Key Import(
            Algorithm algorithm,
            ReadOnlySpan<byte> blob,
            PasswordBasedEncryptionScheme scheme,
            ReadOnlySpan<byte> password,
            in KeyCreationParameters creationParameters = default)
        {
            if (algorithm == null)
            {
                throw new ArgumentNullException(nameof(algorithm));
            }

            KeyBlobFormat format = SelectKeyBlobFormat(algorithm);
            byte[]? plaintext = Decrypt(blob, scheme, password);
            return Key.Import(algorithm, plaintext, format, in creationParameters);
        }

        internal static byte[]? Decrypt(
            ReadOnlySpan<byte> blob,
            PasswordBasedEncryptionScheme scheme,
            string password)
        {
            if (scheme == null)
            {
                throw new ArgumentNullException(nameof(scheme));
            }

            Reader reader = new(blob);
            ReadParametersAndCiphertext(ref reader, scheme, out ReadOnlySpan<byte> salt, out ReadOnlySpan<byte> nonce, out ReadOnlySpan<byte> ciphertext);

            return scheme.Decrypt(password, salt, nonce, ciphertext);
        }

        internal static byte[]? Decrypt(
            ReadOnlySpan<byte> blob,
            PasswordBasedEncryptionScheme scheme,
            ReadOnlySpan<byte> password)
        {
            if (scheme == null)
            {
                throw new ArgumentNullException(nameof(scheme));
            }

            Reader reader = new(blob);
            ReadParametersAndCiphertext(ref reader, scheme, out ReadOnlySpan<byte> salt, out ReadOnlySpan<byte> nonce, out ReadOnlySpan<byte> ciphertext);

            return scheme.Decrypt(password, salt, nonce, ciphertext);
        }

        internal static byte[] Encrypt(
            ReadOnlySpan<byte> plaintext,
            PasswordBasedEncryptionScheme scheme,
            string password,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> nonce)
        {
            if (scheme == null)
            {
                throw new ArgumentNullException(nameof(scheme));
            }

            byte[] ciphertext = scheme.Encrypt(password, salt, nonce, plaintext);

            Writer writer = new(new byte[1000]);
            WriteParametersAndCiphertext(ref writer, scheme, salt, nonce, ciphertext);
            return writer.ToArray();
        }

        internal static byte[] Encrypt(
            ReadOnlySpan<byte> plaintext,
            PasswordBasedEncryptionScheme scheme,
            ReadOnlySpan<byte> password,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> nonce)
        {
            if (scheme == null)
            {
                throw new ArgumentNullException(nameof(scheme));
            }

            byte[] ciphertext = scheme.Encrypt(password, salt, nonce, plaintext);

            Writer writer = new(new byte[1000]);
            WriteParametersAndCiphertext(ref writer, scheme, salt, nonce, ciphertext);
            return writer.ToArray();
        }

        private static KeyBlobFormat SelectKeyBlobFormat(
            Algorithm algorithm)
        {
            return algorithm switch
            {
                AeadAlgorithm _ or MacAlgorithm _ or StreamCipherAlgorithm _ => KeyBlobFormat.NSecSymmetricKey,
                KeyAgreementAlgorithm _ or SignatureAlgorithm _ => KeyBlobFormat.NSecPrivateKey,
                _ => throw new NotSupportedException(),
            };
        }

        private static void ReadParametersAndCiphertext(
            ref Reader reader,
            PasswordBasedEncryptionScheme scheme,
            out ReadOnlySpan<byte> salt,
            out ReadOnlySpan<byte> nonce,
            out ReadOnlySpan<byte> ciphertext)
        {
            Read(ref reader, 0x0000);
            ReadPasswordParameters(ref reader, scheme.KeyDerivationAlgorithm, out salt);
            ReadEncryptionParameters(ref reader, scheme.EncryptionAlgorithm, out nonce);
            Read(ref reader, out ciphertext);
        }

        private static void ReadEncryptionParameters(
            ref Reader reader,
            AeadAlgorithm algorithm,
            out ReadOnlySpan<byte> nonce)
        {
            switch (algorithm)
            {
            case Aes256Gcm _:
                Read(ref reader, 0x2001);
                Read(ref reader, out nonce);
                break;

            case ChaCha20Poly1305 _:
                Read(ref reader, 0x2002);
                Read(ref reader, out nonce);
                break;

            case XChaCha20Poly1305 _:
                Read(ref reader, 0x2003);
                Read(ref reader, out nonce);
                break;

            case Aegis128L _:
                Read(ref reader, 0x2004);
                Read(ref reader, out nonce);
                break;

            case Aegis256 _:
                Read(ref reader, 0x2005);
                Read(ref reader, out nonce);
                break;

            default:
                throw new NotSupportedException();
            }
        }

        private static void ReadPasswordParameters(
            ref Reader reader,
            PasswordBasedKeyDerivationAlgorithm algorithm,
            out ReadOnlySpan<byte> salt)
        {
            switch (algorithm)
            {
            case Argon2i argon2i:
                argon2i.GetParameters(out Argon2Parameters argon2iParameters);
                Read(ref reader, 0x1001);
                Read(ref reader, out salt);
                Read(ref reader, argon2iParameters.DegreeOfParallelism);
                Read(ref reader, argon2iParameters.MemorySize);
                Read(ref reader, argon2iParameters.NumberOfPasses);
                break;

            case Argon2id argon2id:
                argon2id.GetParameters(out Argon2Parameters argon2idParameters);
                Read(ref reader, 0x1002);
                Read(ref reader, out salt);
                Read(ref reader, argon2idParameters.DegreeOfParallelism);
                Read(ref reader, argon2idParameters.MemorySize);
                Read(ref reader, argon2idParameters.NumberOfPasses);
                break;

            case Pbkdf2HmacSha256 pbkdf2HmacSha256:
                pbkdf2HmacSha256.GetParameters(out Pbkdf2Parameters pbkdf2HmacSha256Parameters);
                Read(ref reader, 0x1003);
                Read(ref reader, out salt);
                Read(ref reader, pbkdf2HmacSha256Parameters.IterationCount);
                break;

            case Scrypt scrypt:
                scrypt.GetParameters(out ScryptParameters scryptParameters);
                Read(ref reader, 0x1004);
                Read(ref reader, out salt);
                Read(ref reader, scryptParameters.Cost);
                Read(ref reader, scryptParameters.BlockSize);
                Read(ref reader, scryptParameters.Parallelization);
                break;

            default:
                throw new NotSupportedException();
            };
        }

        private static void WriteParametersAndCiphertext(
            ref Writer writer,
            PasswordBasedEncryptionScheme scheme,
            ReadOnlySpan<byte> salt,
            ReadOnlySpan<byte> nonce,
            ReadOnlySpan<byte> ciphertext)
        {
            Write(ref writer, 0x0000);
            WritePasswordParameters(ref writer, scheme.KeyDerivationAlgorithm, salt);
            WriteEncryptionParameters(ref writer, scheme.EncryptionAlgorithm, nonce);
            Write(ref writer, ciphertext);
        }

        private static void WriteEncryptionParameters(
            ref Writer writer,
            AeadAlgorithm algorithm,
            ReadOnlySpan<byte> nonce)
        {
            switch (algorithm)
            {
            case Aes256Gcm _:
                Write(ref writer, 0x2001);
                Write(ref writer, nonce);
                break;

            case ChaCha20Poly1305 _:
                Write(ref writer, 0x2002);
                Write(ref writer, nonce);
                break;

            case XChaCha20Poly1305 _:
                Write(ref writer, 0x2003);
                Write(ref writer, nonce);
                break;

            case Aegis128L _:
                Write(ref writer, 0x2004);
                Write(ref writer, nonce);
                break;

            case Aegis256 _:
                Write(ref writer, 0x2005);
                Write(ref writer, nonce);
                break;

            default:
                throw new NotSupportedException();
            }
        }

        private static void WritePasswordParameters(
            ref Writer writer,
            PasswordBasedKeyDerivationAlgorithm algorithm,
            ReadOnlySpan<byte> salt)
        {
            switch (algorithm)
            {
            case Argon2i argon2i:
                argon2i.GetParameters(out Argon2Parameters argon2iParameters);
                Write(ref writer, 0x1001);
                Write(ref writer, salt);
                Write(ref writer, argon2iParameters.DegreeOfParallelism);
                Write(ref writer, argon2iParameters.MemorySize);
                Write(ref writer, argon2iParameters.NumberOfPasses);
                break;

            case Argon2id argon2id:
                argon2id.GetParameters(out Argon2Parameters argon2idParameters);
                Write(ref writer, 0x1002);
                Write(ref writer, salt);
                Write(ref writer, argon2idParameters.DegreeOfParallelism);
                Write(ref writer, argon2idParameters.MemorySize);
                Write(ref writer, argon2idParameters.NumberOfPasses);
                break;

            case Pbkdf2HmacSha256 pbkdf2HmacSha256:
                pbkdf2HmacSha256.GetParameters(out Pbkdf2Parameters pbkdf2HmacSha256Parameters);
                Write(ref writer, 0x1003);
                Write(ref writer, salt);
                Write(ref writer, pbkdf2HmacSha256Parameters.IterationCount);
                break;

            case Scrypt scrypt:
                scrypt.GetParameters(out ScryptParameters scryptParameters);
                Write(ref writer, 0x1004);
                Write(ref writer, salt);
                Write(ref writer, scryptParameters.Cost);
                Write(ref writer, scryptParameters.BlockSize);
                Write(ref writer, scryptParameters.Parallelization);
                break;

            default:
                throw new NotSupportedException();
            };
        }

        private static void Read(
            ref Reader reader,
            int value)
        {
            if (value != System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(reader[4]))
            {
                throw new InvalidOperationException();
            }
        }

        private static void Read(
            ref Reader reader,
            long value)
        {
            if (value != System.Buffers.Binary.BinaryPrimitives.ReadInt64LittleEndian(reader[8]))
            {
                throw new InvalidOperationException();
            }
        }

        private static void Read(
            ref Reader reader,
            out ReadOnlySpan<byte> value)
        {
            int length = System.Buffers.Binary.BinaryPrimitives.ReadInt32LittleEndian(reader[4]);
            value = reader[length];
        }

        private static void Write(
            ref Writer writer,
            int value)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(writer[4], value);
        }

        private static void Write(
            ref Writer writer,
            long value)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteInt64LittleEndian(writer[8], value);
        }

        private static void Write(
            ref Writer writer,
            ReadOnlySpan<byte> value)
        {
            System.Buffers.Binary.BinaryPrimitives.WriteInt32LittleEndian(writer[4], value.Length);
            value.CopyTo(writer[value.Length]);
        }

        private ref struct Reader(
            ReadOnlySpan<byte> bytes)
        {
            private readonly ReadOnlySpan<byte> _bytes = bytes;
            private int _pos = 0;

            public ReadOnlySpan<byte> this[
                int length]
            {
                get
                {
                    ReadOnlySpan<byte> span = _bytes.Slice(_pos, length);
                    _pos += length;
                    return span;
                }
            }
        }

        private ref struct Writer(
            Span<byte> bytes)
        {
            private readonly Span<byte> _bytes = bytes;
            private int _pos = 0;

            public Span<byte> this[
                int length]
            {
                get
                {
                    Span<byte> span = _bytes.Slice(_pos, length);
                    _pos += length;
                    return span;
                }
            }

            public readonly byte[] ToArray()
            {
                return _bytes[.._pos].ToArray();
            }
        }
    }
}
