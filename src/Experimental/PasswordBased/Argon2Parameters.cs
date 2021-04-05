using System.Runtime.InteropServices;

namespace NSec.Experimental.PasswordBased
{
    [StructLayout(LayoutKind.Auto)]
    public struct Argon2Parameters
    {
        public int DegreeOfParallelism;
        public long MemorySize;
        public long NumberOfPasses;
    }
}
