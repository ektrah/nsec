using System.Runtime.InteropServices;

namespace NSec.Experimental.PasswordBased
{
    [StructLayout(LayoutKind.Auto)]
    public ref struct Argon2Parameters
    {
        public int DegreeOfParallelism;
        public long MemorySize;
        public int NumberOfPasses;
    }
}
