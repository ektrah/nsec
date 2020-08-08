using System;
using System.Reflection;
using System.Resources;

namespace NSec.Cryptography
{
    internal static class Error
    {
        private static ResourceManager? s_resourceManager;

        private static ResourceManager ResourceManager => s_resourceManager ?? (s_resourceManager = new ResourceManager(typeof(Error).FullName!, typeof(Error).GetTypeInfo().Assembly));

        internal static ArgumentException Argument_BadBase16Length(
            string paramName)
        {
            return new ArgumentException(ResourceManager.GetString(nameof(Argument_BadBase16Length)), paramName);
        }

        internal static ArgumentException Argument_BadBase32Length(
            string paramName)
        {
            return new ArgumentException(ResourceManager.GetString(nameof(Argument_BadBase32Length)), paramName);
        }

        internal static ArgumentException Argument_BadBase64Length(
            string paramName)
        {
            return new ArgumentException(ResourceManager.GetString(nameof(Argument_BadBase64Length)), paramName);
        }

        internal static ArgumentException Argument_CiphertextLength(
            string paramName)
        {
            return new ArgumentException(ResourceManager.GetString(nameof(Argument_CiphertextLength)), paramName);
        }

        internal static ArgumentException Argument_DeriveInvalidCount(
            string paramName,
            object? arg0)
        {
            return new ArgumentException(string.Format(ResourceManager.GetString(nameof(Argument_DeriveInvalidCount))!, arg0), paramName);
        }

        internal static ArgumentException Argument_DestinationTooShort(
            string paramName)
        {
            return new ArgumentException(ResourceManager.GetString(nameof(Argument_DestinationTooShort)), paramName);
        }

        internal static ArgumentException Argument_FormatNotSupported(
            string paramName,
            object? arg0)
        {
            return new ArgumentException(string.Format(ResourceManager.GetString(nameof(Argument_FormatNotSupported))!, arg0), paramName);
        }

        internal static ArgumentException Argument_HashLength(
            string paramName,
            object? arg0)
        {
            return new ArgumentException(string.Format(ResourceManager.GetString(nameof(Argument_HashLength))!, arg0), paramName);
        }

        internal static ArgumentException Argument_InvalidPrkLength(
            string paramName,
            object? arg0)
        {
            return new ArgumentException(string.Format(ResourceManager.GetString(nameof(Argument_InvalidPrkLength))!, arg0), paramName);
        }

        internal static ArgumentException Argument_InvalidPrkLengthExact(
            string paramName,
            object? arg0)
        {
            return new ArgumentException(string.Format(ResourceManager.GetString(nameof(Argument_InvalidPrkLengthExact))!, arg0), paramName);
        }

        internal static ArgumentException Argument_KeyAlgorithmMismatch(
            string paramName,
            object? arg0)
        {
            return new ArgumentException(string.Format(ResourceManager.GetString(nameof(Argument_KeyAlgorithmMismatch))!, arg0), paramName);
        }

        internal static ArgumentException Argument_MacKeyRequired(
            string paramName)
        {
            return new ArgumentException(ResourceManager.GetString(nameof(Argument_MacKeyRequired)), paramName);
        }

        internal static ArgumentException Argument_MacLength(
            string paramName,
            object? arg0)
        {
            return new ArgumentException(string.Format(ResourceManager.GetString(nameof(Argument_MacLength))!, arg0), paramName);
        }

        internal static ArgumentException Argument_MinMaxValue(
            string paramName,
            object? arg0,
            object? arg1)
        {
            return new ArgumentException(string.Format(ResourceManager.GetString(nameof(Argument_MinMaxValue))!, arg0, arg1), paramName);
        }

        internal static ArgumentException Argument_NonceFixedCounterSize(
            string paramName,
            object? arg0)
        {
            return new ArgumentException(string.Format(ResourceManager.GetString(nameof(Argument_NonceFixedCounterSize))!, arg0), paramName);
        }

        internal static ArgumentException Argument_NonceFixedSize(
            string paramName,
            object? arg0)
        {
            return new ArgumentException(string.Format(ResourceManager.GetString(nameof(Argument_NonceFixedSize))!, arg0), paramName);
        }

        internal static ArgumentException Argument_NonceLength(
            string paramName,
            object? arg0)
        {
            return new ArgumentException(string.Format(ResourceManager.GetString(nameof(Argument_NonceLength))!, arg0), paramName);
        }

        internal static ArgumentException Argument_NonceXorSize(
            string paramName)
        {
            return new ArgumentException(ResourceManager.GetString(nameof(Argument_NonceXorSize)), paramName);
        }

        internal static ArgumentException Argument_OverlapCiphertext(
            string paramName)
        {
            return new ArgumentException(ResourceManager.GetString(nameof(Argument_OverlapCiphertext)), paramName);
        }

        internal static ArgumentException Argument_OverlapInfo(
            string paramName)
        {
            return new ArgumentException(ResourceManager.GetString(nameof(Argument_OverlapInfo)), paramName);
        }

        internal static ArgumentException Argument_OverlapPlaintext(
            string paramName)
        {
            return new ArgumentException(ResourceManager.GetString(nameof(Argument_OverlapPlaintext)), paramName);
        }

        internal static ArgumentException Argument_OverlapPrk(
            string paramName)
        {
            return new ArgumentException(ResourceManager.GetString(nameof(Argument_OverlapPrk)), paramName);
        }

        internal static ArgumentException Argument_OverlapSalt(
            string paramName)
        {
            return new ArgumentException(ResourceManager.GetString(nameof(Argument_OverlapSalt)), paramName);
        }

        internal static ArgumentException Argument_PlaintextLength(
            string paramName)
        {
            return new ArgumentException(ResourceManager.GetString(nameof(Argument_PlaintextLength)), paramName);
        }

        internal static ArgumentException Argument_PlaintextTooLong(
            string paramName,
            object? arg0)
        {
            return new ArgumentException(string.Format(ResourceManager.GetString(nameof(Argument_PlaintextTooLong))!, arg0), paramName);
        }

        internal static ArgumentException Argument_PublicKeyAlgorithmMismatch(
            string paramName,
            object? arg0)
        {
            return new ArgumentException(string.Format(ResourceManager.GetString(nameof(Argument_PublicKeyAlgorithmMismatch))!, arg0), paramName);
        }

        internal static ArgumentException Argument_SaltLength(
            string paramName,
            object? arg0)
        {
            return new ArgumentException(string.Format(ResourceManager.GetString(nameof(Argument_SaltLength))!, arg0), paramName);
        }

        internal static ArgumentException Argument_SaltNotSupported(
            string paramName)
        {
            return new ArgumentException(ResourceManager.GetString(nameof(Argument_SaltNotSupported)), paramName);
        }

        internal static ArgumentException Argument_SharedSecretLength(
            string paramName,
            object? arg0)
        {
            return new ArgumentException(string.Format(ResourceManager.GetString(nameof(Argument_SharedSecretLength))!, arg0), paramName);
        }

        internal static ArgumentException Argument_SignatureLength(
            string paramName,
            object? arg0)
        {
            return new ArgumentException(string.Format(ResourceManager.GetString(nameof(Argument_SignatureLength))!, arg0), paramName);
        }

        internal static ArgumentNullException ArgumentNull_Algorithm(
            string paramName)
        {
            return new ArgumentNullException(paramName, ResourceManager.GetString(nameof(ArgumentNull_Algorithm)));
        }

        internal static ArgumentNullException ArgumentNull_Key(
            string paramName)
        {
            return new ArgumentNullException(paramName, ResourceManager.GetString(nameof(ArgumentNull_Key)));
        }

        internal static ArgumentNullException ArgumentNull_Password(
            string paramName)
        {
            return new ArgumentNullException(paramName, ResourceManager.GetString(nameof(ArgumentNull_Password)));
        }

        internal static ArgumentNullException ArgumentNull_SharedSecret(
            string paramName)
        {
            return new ArgumentNullException(paramName, ResourceManager.GetString(nameof(ArgumentNull_SharedSecret)));
        }

        internal static ArgumentNullException ArgumentNull_String(
            string paramName)
        {
            return new ArgumentNullException(paramName, ResourceManager.GetString(nameof(ArgumentNull_String)));
        }

        internal static ArgumentOutOfRangeException ArgumentOutOfRange_DeriveInvalidCount(
            string paramName,
            object? arg0)
        {
            return new ArgumentOutOfRangeException(paramName, string.Format(ResourceManager.GetString(nameof(ArgumentOutOfRange_DeriveInvalidCount))!, arg0));
        }

        internal static ArgumentOutOfRangeException ArgumentOutOfRange_DeriveNegativeCount(
            string paramName)
        {
            return new ArgumentOutOfRangeException(paramName, ResourceManager.GetString(nameof(ArgumentOutOfRange_DeriveNegativeCount)));
        }

        internal static ArgumentOutOfRangeException ArgumentOutOfRange_GenerateNegativeCount(
            string paramName)
        {
            return new ArgumentOutOfRangeException(paramName, ResourceManager.GetString(nameof(ArgumentOutOfRange_GenerateNegativeCount)));
        }

        internal static ArgumentOutOfRangeException ArgumentOutOfRange_HashSize(
            string paramName,
            object? arg0,
            object? arg1,
            object? arg2)
        {
            return new ArgumentOutOfRangeException(paramName, string.Format(ResourceManager.GetString(nameof(ArgumentOutOfRange_HashSize))!, arg0, arg1, arg2));
        }

        internal static ArgumentOutOfRangeException ArgumentOutOfRange_KeySize(
            string paramName,
            object? arg0,
            object? arg1,
            object? arg2)
        {
            return new ArgumentOutOfRangeException(paramName, string.Format(ResourceManager.GetString(nameof(ArgumentOutOfRange_KeySize))!, arg0, arg1, arg2));
        }

        internal static ArgumentOutOfRangeException ArgumentOutOfRange_MacSize(
            string paramName,
            object? arg0,
            object? arg1,
            object? arg2)
        {
            return new ArgumentOutOfRangeException(paramName, string.Format(ResourceManager.GetString(nameof(ArgumentOutOfRange_MacSize))!, arg0, arg1, arg2));
        }

        internal static ArgumentOutOfRangeException ArgumentOutOfRange_MustBePositive(
            string paramName,
            object? arg0)
        {
            return new ArgumentOutOfRangeException(paramName, string.Format(ResourceManager.GetString(nameof(ArgumentOutOfRange_MustBePositive))!, arg0));
        }

        internal static ArgumentOutOfRangeException ArgumentOutOfRange_NonceAddend(
            string paramName)
        {
            return new ArgumentOutOfRangeException(paramName, ResourceManager.GetString(nameof(ArgumentOutOfRange_NonceAddend)));
        }

        internal static ArgumentOutOfRangeException ArgumentOutOfRange_NonceCounterSize(
            string paramName,
            object? arg0)
        {
            return new ArgumentOutOfRangeException(paramName, string.Format(ResourceManager.GetString(nameof(ArgumentOutOfRange_NonceCounterSize))!, arg0));
        }

        internal static ArgumentOutOfRangeException ArgumentOutOfRange_NonceFixedCounterSize(
            string paramName,
            object? arg0)
        {
            return new ArgumentOutOfRangeException(paramName, string.Format(ResourceManager.GetString(nameof(ArgumentOutOfRange_NonceFixedCounterSize))!, arg0));
        }

        internal static FormatException Format_BadBase16()
        {
            return new FormatException(ResourceManager.GetString(nameof(Format_BadBase16)));
        }

        internal static FormatException Format_BadBase32()
        {
            return new FormatException(ResourceManager.GetString(nameof(Format_BadBase32)));
        }

        internal static FormatException Format_BadBase64()
        {
            return new FormatException(ResourceManager.GetString(nameof(Format_BadBase64)));
        }

        internal static FormatException Format_InvalidBlob()
        {
            return new FormatException(ResourceManager.GetString(nameof(Format_InvalidBlob)));
        }

        internal static InvalidOperationException InvalidOperation_AlreadyArchived()
        {
            return new InvalidOperationException(ResourceManager.GetString(nameof(InvalidOperation_AlreadyArchived)));
        }

        internal static InvalidOperationException InvalidOperation_ExportNotAllowed()
        {
            return new InvalidOperationException(ResourceManager.GetString(nameof(InvalidOperation_ExportNotAllowed)));
        }

        internal static InvalidOperationException InvalidOperation_InitializationFailed()
        {
            return new InvalidOperationException(ResourceManager.GetString(nameof(InvalidOperation_InitializationFailed)));
        }

        internal static InvalidOperationException InvalidOperation_InitializationFailed_VersionMismatch(
            object? arg0,
            object? arg1)
        {
            return new InvalidOperationException(string.Format(ResourceManager.GetString(nameof(InvalidOperation_InitializationFailed_VersionMismatch))!, arg0, arg1));
        }

        internal static InvalidOperationException InvalidOperation_InternalError()
        {
            return new InvalidOperationException(ResourceManager.GetString(nameof(InvalidOperation_InternalError)));
        }

        internal static InvalidOperationException InvalidOperation_NoPublicKey()
        {
            return new InvalidOperationException(ResourceManager.GetString(nameof(InvalidOperation_NoPublicKey)));
        }

        internal static InvalidOperationException InvalidOperation_UninitializedState()
        {
            return new InvalidOperationException(ResourceManager.GetString(nameof(InvalidOperation_UninitializedState)));
        }

        internal static NotSupportedException NotSupported_CreateKey()
        {
            return new NotSupportedException(ResourceManager.GetString(nameof(NotSupported_CreateKey)));
        }

        internal static NotSupportedException NotSupported_ExportKey()
        {
            return new NotSupportedException(ResourceManager.GetString(nameof(NotSupported_ExportKey)));
        }

        internal static NotSupportedException NotSupported_ImportKey()
        {
            return new NotSupportedException(ResourceManager.GetString(nameof(NotSupported_ImportKey)));
        }

        internal static NotSupportedException NotSupported_Operation()
        {
            return new NotSupportedException(ResourceManager.GetString(nameof(NotSupported_Operation)));
        }

        internal static OverflowException Overflow_NonceCounter()
        {
            return new OverflowException(ResourceManager.GetString(nameof(Overflow_NonceCounter)));
        }

        internal static PlatformNotSupportedException PlatformNotSupported_Algorithm()
        {
            return new PlatformNotSupportedException(ResourceManager.GetString(nameof(PlatformNotSupported_Algorithm)));
        }

        internal static PlatformNotSupportedException PlatformNotSupported_Initialization(
            Exception innerException)
        {
            return new PlatformNotSupportedException(ResourceManager.GetString(nameof(PlatformNotSupported_Initialization)), innerException);
        }
    }
}
