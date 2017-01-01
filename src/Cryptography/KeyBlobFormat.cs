namespace NSec.Cryptography
{
    public enum KeyBlobFormat
    {
        None = 0,

        // --- Secret Key Formats ---

        RawSymmetricKey = -1,
        RawPrivateKey = -2,

        NSecSymmetricKey = -101,
        NSecPrivateKey = -102,

        // --- Public Key Formats ---

        RawPublicKey = 1,

        NSecPublicKey = 101,
    }
}
