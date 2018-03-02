/** libkeccak-tiny
 *
 * A single-file implementation of SHA-3 and SHAKE.
 *
 * Implementor: David Leon Gil
 * License: CC0, attribution kindly requested. Blame taken too,
 * but not liability.
 */

namespace NSec.Cryptography.Experimental
{
internal static partial class KeccakTiny
{

/******** The Keccak-f[1600] permutation ********/

/*** Constants. ***/
private static readonly byte[] rho =
  { 1, 3, 6, 10, 15, 21,
    28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43,
    62, 18, 39, 61, 20, 44};
private static readonly byte[] pi =
  {10, 7, 11, 17, 18, 3,
    5, 16, 8, 21, 24, 4,
   15, 23, 19, 13, 12, 2,
   20, 14, 22, 9, 6, 1};
private static readonly ulong[] RC =
  {1UL, 0x8082UL, 0x800000000000808aUL, 0x8000000080008000UL,
   0x808bUL, 0x80000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
   0x8aUL, 0x88UL, 0x80008009UL, 0x8000000aUL,
   0x8000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
   0x8000000000008002UL, 0x8000000000000080UL, 0x800aUL, 0x800000008000000aUL,
   0x8000000080008081UL, 0x8000000000008080UL, 0x80000001UL, 0x8000000080008008UL};

/*** Helper macros to unroll the permutation. ***/
/*** Keccak-f[1600] ***/
private static unsafe void keccakf(void* state) {
  ulong* a = (ulong*)state;
  ulong* b = stackalloc ulong[5];
  ulong t = 0;
  byte x, y;

  for (int i = 0; i < 24; i++) {
    // Theta
    x = 0; b[x] = 0; y = 0; b[x] ^= a[x + y];; y += 5; b[x] ^= a[x + y];; y += 5; b[x] ^= a[x + y];; y += 5; b[x] ^= a[x + y];; y += 5; b[x] ^= a[x + y];; y += 5;; x += 1; b[x] = 0; y = 0; b[x] ^= a[x + y];; y += 5; b[x] ^= a[x + y];; y += 5; b[x] ^= a[x + y];; y += 5; b[x] ^= a[x + y];; y += 5; b[x] ^= a[x + y];; y += 5;; x += 1; b[x] = 0; y = 0; b[x] ^= a[x + y];; y += 5; b[x] ^= a[x + y];; y += 5; b[x] ^= a[x + y];; y += 5; b[x] ^= a[x + y];; y += 5; b[x] ^= a[x + y];; y += 5;; x += 1; b[x] = 0; y = 0; b[x] ^= a[x + y];; y += 5; b[x] ^= a[x + y];; y += 5; b[x] ^= a[x + y];; y += 5; b[x] ^= a[x + y];; y += 5; b[x] ^= a[x + y];; y += 5;; x += 1; b[x] = 0; y = 0; b[x] ^= a[x + y];; y += 5; b[x] ^= a[x + y];; y += 5; b[x] ^= a[x + y];; y += 5; b[x] ^= a[x + y];; y += 5; b[x] ^= a[x + y];; y += 5;; x += 1;



    x = 0; y = 0; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5;; x += 1; y = 0; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5;; x += 1; y = 0; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5;; x += 1; y = 0; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5;; x += 1; y = 0; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5; a[y + x] ^= b[(x + 4) % 5] ^ (((b[(x + 1) % 5]) << 1) | ((b[(x + 1) % 5]) >> (64 - 1)));; y += 5;; x += 1;


    // Rho and pi
    t = a[1];
    x = 0;
    b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++; b[0] = a[pi[x]]; a[pi[x]] = (((t) << rho[x]) | ((t) >> (64 - rho[x]))); t = b[0]; x++;



    // Chi
    y = 0; x = 0; b[x] = a[y + x];; x += 1; b[x] = a[y + x];; x += 1; b[x] = a[y + x];; x += 1; b[x] = a[y + x];; x += 1; b[x] = a[y + x];; x += 1; x = 0; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1;; y += 5; x = 0; b[x] = a[y + x];; x += 1; b[x] = a[y + x];; x += 1; b[x] = a[y + x];; x += 1; b[x] = a[y + x];; x += 1; b[x] = a[y + x];; x += 1; x = 0; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1;; y += 5; x = 0; b[x] = a[y + x];; x += 1; b[x] = a[y + x];; x += 1; b[x] = a[y + x];; x += 1; b[x] = a[y + x];; x += 1; b[x] = a[y + x];; x += 1; x = 0; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1;; y += 5; x = 0; b[x] = a[y + x];; x += 1; b[x] = a[y + x];; x += 1; b[x] = a[y + x];; x += 1; b[x] = a[y + x];; x += 1; b[x] = a[y + x];; x += 1; x = 0; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1;; y += 5; x = 0; b[x] = a[y + x];; x += 1; b[x] = a[y + x];; x += 1; b[x] = a[y + x];; x += 1; b[x] = a[y + x];; x += 1; b[x] = a[y + x];; x += 1; x = 0; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1; a[y + x] = b[x] ^ ((~b[(x + 1) % 5]) & b[(x + 2) % 5]);; x += 1;; y += 5;





    // Iota
    a[0] ^= RC[i];
  }
}

/******** The FIPS202-defined functions. ********/

/*** Some helper macros. ***/
private static unsafe void xorin(byte* dst, byte* src, ulong len) { do { for (ulong i = 0; i < len; i += 1) { dst[i] ^= src[i]; } } while (false); } // xorin
private static unsafe void setout(byte* src, byte* dst, ulong len) { do { for (ulong i = 0; i < len; i += 1) { dst[i] = src[i]; } } while (false); } // setout




// Fold P*F over the full blocks of an input.
/** The sponge-based hash construction. **/
private static unsafe int hash(byte* @out, ulong outlen,
                       byte* @in, ulong inlen,
                       ulong rate, byte delim) {
  if ((@out == null) || ((@in == null) && inlen != 0) || (rate >= 200)) {
    return -1;
  }
  byte* a = stackalloc byte[200];
  // Absorb input.
  while (inlen >= rate) { xorin(a, @in, rate); keccakf(a); @in += rate; inlen -= rate; };
  // Xor in the DS and pad frame.
  a[inlen] ^= delim;
  a[rate - 1] ^= 0x80;
  // Xor in the last block.
  xorin(a, @in, inlen);
  // Apply P
  keccakf(a);
  // Squeeze output.
  while (outlen >= rate) { setout(a, @out, rate); keccakf(a); @out += rate; outlen -= rate; };
  setout(a, @out, outlen);
  //memset_s(a, 200, 0, 200);
  return 0;
}

/*** Helper macros to define SHA3 and SHAKE instances. ***/
/*** FIPS202 SHAKE VOFs ***/
public static unsafe int shake128(ref byte @out, ulong outlen, ref byte @in, ulong inlen) { fixed (byte* _out = &@out) fixed (byte* _in = &@in) { return hash(_out, outlen, _in, inlen, 200 - (128 / 4), 0x1f); } }
public static unsafe int shake256(ref byte @out, ulong outlen, ref byte @in, ulong inlen) { fixed (byte* _out = &@out) fixed (byte* _in = &@in) { return hash(_out, outlen, _in, inlen, 200 - (256 / 4), 0x1f); } }

/*** FIPS202 SHA3 FOFs ***/
public static unsafe int sha3_224(ref byte @out, ulong outlen, ref byte @in, ulong inlen) { if (outlen > (224/8)) { return -1; } fixed (byte* _out = &@out) fixed (byte* _in = &@in) { return hash(_out, outlen, _in, inlen, 200 - (224 / 4), 0x06); } }
public static unsafe int sha3_256(ref byte @out, ulong outlen, ref byte @in, ulong inlen) { if (outlen > (256/8)) { return -1; } fixed (byte* _out = &@out) fixed (byte* _in = &@in) { return hash(_out, outlen, _in, inlen, 200 - (256 / 4), 0x06); } }
public static unsafe int sha3_384(ref byte @out, ulong outlen, ref byte @in, ulong inlen) { if (outlen > (384/8)) { return -1; } fixed (byte* _out = &@out) fixed (byte* _in = &@in) { return hash(_out, outlen, _in, inlen, 200 - (384 / 4), 0x06); } }
public static unsafe int sha3_512(ref byte @out, ulong outlen, ref byte @in, ulong inlen) { if (outlen > (512/8)) { return -1; } fixed (byte* _out = &@out) fixed (byte* _in = &@in) { return hash(_out, outlen, _in, inlen, 200 - (512 / 4), 0x06); } }

}
}
