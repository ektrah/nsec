internal static partial class Interop
{
    private static class Libraries
    {
#if IOS || TVOS || MACCATALYST
        internal const string Libsodium = "__Internal";
#else
        internal const string Libsodium = "libsodium";
#endif
    }
}
