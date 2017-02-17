using System;
using System.Runtime.CompilerServices;
using static Interop.Libsodium;
/*
 * NORX reference source code package - reference C implementations
 *
 * Written 2014-2016 by:
 *
 *      - Samuel Neves <sneves@dei.uc.pt>
 *      - Philipp Jovanovic <philipp@jovanovic.io>
 *
 * To the extent possible under law, the author(s) have dedicated all copyright
 * and related and neighboring rights to this software to the public domain
 * worldwide. This software is distributed without any warranty.
 *
 * You should have received a copy of the CC0 Public Domain Dedication along with
 * this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
 */










using norx_word_t = System.UInt64;

internal static partial class Interop
{
internal static partial class Norx6441
{

static unsafe void memset(byte* dst, byte v, ulong length)
{
    Unsafe.InitBlockUnaligned(dst, v, (uint)length);
}

static unsafe void memcpy(byte* dst, byte* src, ulong length)
{
    Unsafe.CopyBlockUnaligned(dst, src, (uint)length);
}
static unsafe uint load32( void * @in)
{
    return Unsafe.Read<uint>(@in);
}


static unsafe ulong load64( void * @in)
{
    return Unsafe.Read<ulong>(@in);
}


static unsafe void store32(void * @out, uint v)
{
    Unsafe.Write(@out, v);
}


static unsafe void store64(void * @out, ulong v)
{
    Unsafe.Write(@out, v);
}




struct norx_state_t
{
    public unsafe fixed norx_word_t S[16];
}

enum tag_t
{
    HEADER_TAG = 0x01,
    PAYLOAD_TAG = 0x02,
    TRAILER_TAG = 0x04,
    FINAL_TAG = 0x08,
    BRANCH_TAG = 0x10,
    MERGE_TAG = 0x20
}
    /* Rotation constants */
/* The nonlinear primitive */


/* The quarter-round */
/* The full round */
static unsafe void F(norx_word_t* S)
{
    /* Column step */
    do { (S[ 0]) = ( ( (S[ 0]) ^ (S[ 4]) ) ^ ( ( (S[ 0]) & (S[ 4]) ) << 1) ); (S[12]) ^= (S[ 0]); (S[12]) = ( (((S[12])) >> (8)) | (((S[12])) << (- (8))) ); (S[ 8]) = ( ( (S[ 8]) ^ (S[12]) ) ^ ( ( (S[ 8]) & (S[12]) ) << 1) ); (S[ 4]) ^= (S[ 8]); (S[ 4]) = ( (((S[ 4])) >> (19)) | (((S[ 4])) << (- (19))) ); (S[ 0]) = ( ( (S[ 0]) ^ (S[ 4]) ) ^ ( ( (S[ 0]) & (S[ 4]) ) << 1) ); (S[12]) ^= (S[ 0]); (S[12]) = ( (((S[12])) >> (40)) | (((S[12])) << (- (40))) ); (S[ 8]) = ( ( (S[ 8]) ^ (S[12]) ) ^ ( ( (S[ 8]) & (S[12]) ) << 1) ); (S[ 4]) ^= (S[ 8]); (S[ 4]) = ( (((S[ 4])) >> (63)) | (((S[ 4])) << (- (63))) ); } while (false);
    do { (S[ 1]) = ( ( (S[ 1]) ^ (S[ 5]) ) ^ ( ( (S[ 1]) & (S[ 5]) ) << 1) ); (S[13]) ^= (S[ 1]); (S[13]) = ( (((S[13])) >> (8)) | (((S[13])) << (- (8))) ); (S[ 9]) = ( ( (S[ 9]) ^ (S[13]) ) ^ ( ( (S[ 9]) & (S[13]) ) << 1) ); (S[ 5]) ^= (S[ 9]); (S[ 5]) = ( (((S[ 5])) >> (19)) | (((S[ 5])) << (- (19))) ); (S[ 1]) = ( ( (S[ 1]) ^ (S[ 5]) ) ^ ( ( (S[ 1]) & (S[ 5]) ) << 1) ); (S[13]) ^= (S[ 1]); (S[13]) = ( (((S[13])) >> (40)) | (((S[13])) << (- (40))) ); (S[ 9]) = ( ( (S[ 9]) ^ (S[13]) ) ^ ( ( (S[ 9]) & (S[13]) ) << 1) ); (S[ 5]) ^= (S[ 9]); (S[ 5]) = ( (((S[ 5])) >> (63)) | (((S[ 5])) << (- (63))) ); } while (false);
    do { (S[ 2]) = ( ( (S[ 2]) ^ (S[ 6]) ) ^ ( ( (S[ 2]) & (S[ 6]) ) << 1) ); (S[14]) ^= (S[ 2]); (S[14]) = ( (((S[14])) >> (8)) | (((S[14])) << (- (8))) ); (S[10]) = ( ( (S[10]) ^ (S[14]) ) ^ ( ( (S[10]) & (S[14]) ) << 1) ); (S[ 6]) ^= (S[10]); (S[ 6]) = ( (((S[ 6])) >> (19)) | (((S[ 6])) << (- (19))) ); (S[ 2]) = ( ( (S[ 2]) ^ (S[ 6]) ) ^ ( ( (S[ 2]) & (S[ 6]) ) << 1) ); (S[14]) ^= (S[ 2]); (S[14]) = ( (((S[14])) >> (40)) | (((S[14])) << (- (40))) ); (S[10]) = ( ( (S[10]) ^ (S[14]) ) ^ ( ( (S[10]) & (S[14]) ) << 1) ); (S[ 6]) ^= (S[10]); (S[ 6]) = ( (((S[ 6])) >> (63)) | (((S[ 6])) << (- (63))) ); } while (false);
    do { (S[ 3]) = ( ( (S[ 3]) ^ (S[ 7]) ) ^ ( ( (S[ 3]) & (S[ 7]) ) << 1) ); (S[15]) ^= (S[ 3]); (S[15]) = ( (((S[15])) >> (8)) | (((S[15])) << (- (8))) ); (S[11]) = ( ( (S[11]) ^ (S[15]) ) ^ ( ( (S[11]) & (S[15]) ) << 1) ); (S[ 7]) ^= (S[11]); (S[ 7]) = ( (((S[ 7])) >> (19)) | (((S[ 7])) << (- (19))) ); (S[ 3]) = ( ( (S[ 3]) ^ (S[ 7]) ) ^ ( ( (S[ 3]) & (S[ 7]) ) << 1) ); (S[15]) ^= (S[ 3]); (S[15]) = ( (((S[15])) >> (40)) | (((S[15])) << (- (40))) ); (S[11]) = ( ( (S[11]) ^ (S[15]) ) ^ ( ( (S[11]) & (S[15]) ) << 1) ); (S[ 7]) ^= (S[11]); (S[ 7]) = ( (((S[ 7])) >> (63)) | (((S[ 7])) << (- (63))) ); } while (false);
    /* Diagonal step */
    do { (S[ 0]) = ( ( (S[ 0]) ^ (S[ 5]) ) ^ ( ( (S[ 0]) & (S[ 5]) ) << 1) ); (S[15]) ^= (S[ 0]); (S[15]) = ( (((S[15])) >> (8)) | (((S[15])) << (- (8))) ); (S[10]) = ( ( (S[10]) ^ (S[15]) ) ^ ( ( (S[10]) & (S[15]) ) << 1) ); (S[ 5]) ^= (S[10]); (S[ 5]) = ( (((S[ 5])) >> (19)) | (((S[ 5])) << (- (19))) ); (S[ 0]) = ( ( (S[ 0]) ^ (S[ 5]) ) ^ ( ( (S[ 0]) & (S[ 5]) ) << 1) ); (S[15]) ^= (S[ 0]); (S[15]) = ( (((S[15])) >> (40)) | (((S[15])) << (- (40))) ); (S[10]) = ( ( (S[10]) ^ (S[15]) ) ^ ( ( (S[10]) & (S[15]) ) << 1) ); (S[ 5]) ^= (S[10]); (S[ 5]) = ( (((S[ 5])) >> (63)) | (((S[ 5])) << (- (63))) ); } while (false);
    do { (S[ 1]) = ( ( (S[ 1]) ^ (S[ 6]) ) ^ ( ( (S[ 1]) & (S[ 6]) ) << 1) ); (S[12]) ^= (S[ 1]); (S[12]) = ( (((S[12])) >> (8)) | (((S[12])) << (- (8))) ); (S[11]) = ( ( (S[11]) ^ (S[12]) ) ^ ( ( (S[11]) & (S[12]) ) << 1) ); (S[ 6]) ^= (S[11]); (S[ 6]) = ( (((S[ 6])) >> (19)) | (((S[ 6])) << (- (19))) ); (S[ 1]) = ( ( (S[ 1]) ^ (S[ 6]) ) ^ ( ( (S[ 1]) & (S[ 6]) ) << 1) ); (S[12]) ^= (S[ 1]); (S[12]) = ( (((S[12])) >> (40)) | (((S[12])) << (- (40))) ); (S[11]) = ( ( (S[11]) ^ (S[12]) ) ^ ( ( (S[11]) & (S[12]) ) << 1) ); (S[ 6]) ^= (S[11]); (S[ 6]) = ( (((S[ 6])) >> (63)) | (((S[ 6])) << (- (63))) ); } while (false);
    do { (S[ 2]) = ( ( (S[ 2]) ^ (S[ 7]) ) ^ ( ( (S[ 2]) & (S[ 7]) ) << 1) ); (S[13]) ^= (S[ 2]); (S[13]) = ( (((S[13])) >> (8)) | (((S[13])) << (- (8))) ); (S[ 8]) = ( ( (S[ 8]) ^ (S[13]) ) ^ ( ( (S[ 8]) & (S[13]) ) << 1) ); (S[ 7]) ^= (S[ 8]); (S[ 7]) = ( (((S[ 7])) >> (19)) | (((S[ 7])) << (- (19))) ); (S[ 2]) = ( ( (S[ 2]) ^ (S[ 7]) ) ^ ( ( (S[ 2]) & (S[ 7]) ) << 1) ); (S[13]) ^= (S[ 2]); (S[13]) = ( (((S[13])) >> (40)) | (((S[13])) << (- (40))) ); (S[ 8]) = ( ( (S[ 8]) ^ (S[13]) ) ^ ( ( (S[ 8]) & (S[13]) ) << 1) ); (S[ 7]) ^= (S[ 8]); (S[ 7]) = ( (((S[ 7])) >> (63)) | (((S[ 7])) << (- (63))) ); } while (false);
    do { (S[ 3]) = ( ( (S[ 3]) ^ (S[ 4]) ) ^ ( ( (S[ 3]) & (S[ 4]) ) << 1) ); (S[14]) ^= (S[ 3]); (S[14]) = ( (((S[14])) >> (8)) | (((S[14])) << (- (8))) ); (S[ 9]) = ( ( (S[ 9]) ^ (S[14]) ) ^ ( ( (S[ 9]) & (S[14]) ) << 1) ); (S[ 4]) ^= (S[ 9]); (S[ 4]) = ( (((S[ 4])) >> (19)) | (((S[ 4])) << (- (19))) ); (S[ 3]) = ( ( (S[ 3]) ^ (S[ 4]) ) ^ ( ( (S[ 3]) & (S[ 4]) ) << 1) ); (S[14]) ^= (S[ 3]); (S[14]) = ( (((S[14])) >> (40)) | (((S[14])) << (- (40))) ); (S[ 9]) = ( ( (S[ 9]) ^ (S[14]) ) ^ ( ( (S[ 9]) & (S[14]) ) << 1) ); (S[ 4]) ^= (S[ 9]); (S[ 4]) = ( (((S[ 4])) >> (63)) | (((S[ 4])) << (- (63))) ); } while (false);
}

/* The core permutation */
static unsafe void norx_permute(norx_state_t* state)
{
    ulong i;
    norx_word_t * S = state->S;

    for (i = 0; i < 4; ++i) {
        F(S);
    }
}

static unsafe void norx_pad(byte *@out, byte *@in, ulong inlen)
{
    memset(@out, 0, (((((64 * 16) - (64 * 4))) + 7) / 8));
    memcpy(@out, @in, inlen);
    @out[inlen] = 0x01;
    @out[(((((64 * 16) - (64 * 4))) + 7) / 8) - 1] |= 0x80;
}

static unsafe void norx_absorb_block(norx_state_t* state, byte * @in, tag_t tag)
{
    ulong i;
    norx_word_t * S = state->S;

    S[15] ^= (norx_word_t)tag;
    norx_permute(state);

    for (i = 0; i < (((((64 * 16) - (64 * 4))) + (64 -1)) / 64); ++i) {
        S[i] ^= load64(@in + i * (((64) + 7) / 8));
    }
}

static unsafe void norx_absorb_lastblock(norx_state_t* state, byte * @in, ulong inlen, tag_t tag)
{
    byte* lastblock = stackalloc byte[(((((64 * 16) - (64 * 4))) + 7) / 8)];
    norx_pad(lastblock, @in, inlen);
    norx_absorb_block(state, lastblock, tag);
}

static unsafe void norx_encrypt_block(norx_state_t* state, byte *@out, byte * @in)
{
    ulong i;
    norx_word_t * S = state->S;

    S[15] ^= (norx_word_t)tag_t.PAYLOAD_TAG;
    norx_permute(state);

    for (i = 0; i < (((((64 * 16) - (64 * 4))) + (64 -1)) / 64); ++i) {
        S[i] ^= load64(@in + i * (((64) + 7) / 8));
        store64(@out + i * (((64) + 7) / 8), S[i]);
    }
}

static unsafe void norx_encrypt_lastblock(norx_state_t* state, byte *@out, byte * @in, ulong inlen)
{
    byte* lastblock = stackalloc byte[(((((64 * 16) - (64 * 4))) + 7) / 8)];
    norx_pad(lastblock, @in, inlen);
    norx_encrypt_block(state, lastblock, lastblock);
    memcpy(@out, lastblock, inlen);
}

static unsafe void norx_decrypt_block(norx_state_t* state, byte *@out, byte * @in)
{
    ulong i;
    norx_word_t * S = state->S;

    S[15] ^= (norx_word_t)tag_t.PAYLOAD_TAG;
    norx_permute(state);

    for (i = 0; i < (((((64 * 16) - (64 * 4))) + (64 -1)) / 64); ++i) {
              norx_word_t c = load64(@in + i * (((64) + 7) / 8));
        store64(@out + i * (((64) + 7) / 8), S[i] ^ c);
        S[i] = c;
    }
}

static unsafe void norx_decrypt_lastblock(norx_state_t* state, byte *@out, byte * @in, ulong inlen)
{
    norx_word_t * S = state->S;
    byte* lastblock = stackalloc byte[(((((64 * 16) - (64 * 4))) + 7) / 8)];
    ulong i;

    S[15] ^= (norx_word_t)tag_t.PAYLOAD_TAG;
    norx_permute(state);

    for(i = 0; i < (((((64 * 16) - (64 * 4))) + (64 -1)) / 64); ++i) {
        store64(lastblock + i * (((64) + 7) / 8), S[i]);
    }

    memcpy(lastblock, @in, inlen);
    lastblock[inlen] ^= 0x01;
    lastblock[(((((64 * 16) - (64 * 4))) + 7) / 8) - 1] ^= 0x80;

    for (i = 0; i < (((((64 * 16) - (64 * 4))) + (64 -1)) / 64); ++i) {
              norx_word_t c = load64(lastblock + i * (((64) + 7) / 8));
        store64(lastblock + i * (((64) + 7) / 8), S[i] ^ c);
        S[i] = c;
    }

    memcpy(@out, lastblock, inlen);
    memset(lastblock, 0, (((((64 * 16) - (64 * 4))) + 7) / 8));
}

/* Low-level operations */
static unsafe void norx_init(norx_state_t* state, byte *k, byte *n)
{
    norx_word_t * S = state->S;
    ulong i;

    for(i = 0; i < 16; ++i) {
        S[i] = (norx_word_t)i;
    }

    F(S);
    F(S);

    S[ 0] = load64(n + 0 * (((64) + 7) / 8));
    S[ 1] = load64(n + 1 * (((64) + 7) / 8));
    S[ 2] = load64(n + 2 * (((64) + 7) / 8));
    S[ 3] = load64(n + 3 * (((64) + 7) / 8));

    S[ 4] = load64(k + 0 * (((64) + 7) / 8));
    S[ 5] = load64(k + 1 * (((64) + 7) / 8));
    S[ 6] = load64(k + 2 * (((64) + 7) / 8));
    S[ 7] = load64(k + 3 * (((64) + 7) / 8));

    S[12] ^= 64;
    S[13] ^= 4;
    S[14] ^= 1;
    S[15] ^= (64 * 4);

    norx_permute(state);

    S[12] ^= load64(k + 0 * (((64) + 7) / 8));
    S[13] ^= load64(k + 1 * (((64) + 7) / 8));
    S[14] ^= load64(k + 2 * (((64) + 7) / 8));
    S[15] ^= load64(k + 3 * (((64) + 7) / 8));





}

static unsafe void norx_absorb_data(norx_state_t* state, byte * @in, ulong inlen, tag_t tag)
{
    if (inlen > 0)
    {
        while (inlen >= (((((64 * 16) - (64 * 4))) + 7) / 8))
        {
            norx_absorb_block(state, @in, tag);




            inlen -= (((((64 * 16) - (64 * 4))) + 7) / 8);
            @in += (((((64 * 16) - (64 * 4))) + 7) / 8);
        }
        norx_absorb_lastblock(state, @in, inlen, tag);




    }
}
static unsafe void norx_encrypt_data(norx_state_t* state, byte *@out, byte * @in, ulong inlen)
{
    if (inlen > 0)
    {
        while (inlen >= (((((64 * 16) - (64 * 4))) + 7) / 8))
        {
            norx_encrypt_block(state, @out, @in);




            inlen -= (((((64 * 16) - (64 * 4))) + 7) / 8);
            @in += (((((64 * 16) - (64 * 4))) + 7) / 8);
            @out += (((((64 * 16) - (64 * 4))) + 7) / 8);
        }
        norx_encrypt_lastblock(state, @out, @in, inlen);




    }
}

static unsafe void norx_decrypt_data(norx_state_t* state, byte *@out, byte * @in, ulong inlen)
{
    if (inlen > 0)
    {
        while (inlen >= (((((64 * 16) - (64 * 4))) + 7) / 8))
        {
            norx_decrypt_block(state, @out, @in);




            inlen -= (((((64 * 16) - (64 * 4))) + 7) / 8);
            @in += (((((64 * 16) - (64 * 4))) + 7) / 8);
            @out += (((((64 * 16) - (64 * 4))) + 7) / 8);
        }
        norx_decrypt_lastblock(state, @out, @in, inlen);




    }
}
static unsafe void norx_finalise(norx_state_t* state, byte * tag, byte * k)
{
    norx_word_t * S = state->S;
    byte* lastblock = stackalloc byte[((((64 * 4)) + 7) / 8)];

    S[15] ^= (norx_word_t)tag_t.FINAL_TAG;

    norx_permute(state);

    S[12] ^= load64(k + 0 * (((64) + 7) / 8));
    S[13] ^= load64(k + 1 * (((64) + 7) / 8));
    S[14] ^= load64(k + 2 * (((64) + 7) / 8));
    S[15] ^= load64(k + 3 * (((64) + 7) / 8));

    norx_permute(state);

    S[12] ^= load64(k + 0 * (((64) + 7) / 8));
    S[13] ^= load64(k + 1 * (((64) + 7) / 8));
    S[14] ^= load64(k + 2 * (((64) + 7) / 8));
    S[15] ^= load64(k + 3 * (((64) + 7) / 8));

    store64(lastblock + 0 * (((64) + 7) / 8), S[12]);
    store64(lastblock + 1 * (((64) + 7) / 8), S[13]);
    store64(lastblock + 2 * (((64) + 7) / 8), S[14]);
    store64(lastblock + 3 * (((64) + 7) / 8), S[15]);

    memcpy(tag, lastblock, ((((64 * 4)) + 7) / 8));






    memset(lastblock, 0, ((((64 * 4)) + 7) / 8)); /* burn buffer */
    *state = default(norx_state_t); /* at this point we can also burn the state */
}

/* Verify tags in constant time: 0 for success, -1 for fail */
static unsafe int norx_verify_tag( byte * tag1, byte * tag2)
{
    ulong i;
    int acc = 0;

    for (i = 0; i < ((((64 * 4)) + 7) / 8); ++i) {
        acc |= tag1[i] ^ tag2[i];
    }

    return (((acc - 1) >> 8) & 1) - 1;
}

/* High-level operations */
static unsafe void norx_aead_encrypt(
  byte *c, ulong *clen,
  byte *a, ulong alen,
  byte *m, ulong mlen,
  byte *z, ulong zlen,
  byte *nonce,
  byte *key
)
{
    byte* k = stackalloc byte[((((64 * 4)) + 7) / 8)];
    norx_state_t * state = stackalloc norx_state_t[1];

    memcpy(k, key, ((((64 * 4)) + 7) / 8));
    norx_init(state, k, nonce);
    norx_absorb_data(state, a, alen, tag_t.HEADER_TAG);
    norx_encrypt_data(state, c, m, mlen);
    norx_absorb_data(state, z, zlen, tag_t.TRAILER_TAG);
    norx_finalise(state, c + mlen, k);
    *clen = mlen + ((((64 * 4)) + 7) / 8);
    *state = default(norx_state_t);
    memset(k, 0, ((((64 * 4)) + 7) / 8));
}

static unsafe int norx_aead_decrypt(
  byte *m, ulong *mlen,
  byte *a, ulong alen,
  byte *c, ulong clen,
  byte *z, ulong zlen,
  byte *nonce,
  byte *key
)
{
    byte* k = stackalloc byte[((((64 * 4)) + 7) / 8)];
    byte* tag = stackalloc byte[((((64 * 4)) + 7) / 8)];
    norx_state_t* state = stackalloc norx_state_t[1];
    int result = -1;

    if (clen < ((((64 * 4)) + 7) / 8)) {
        return -1;
    }

    memcpy(k, key, ((((64 * 4)) + 7) / 8));
    norx_init(state, k, nonce);
    norx_absorb_data(state, a, alen, tag_t.HEADER_TAG);
    norx_decrypt_data(state, m, c, clen - ((((64 * 4)) + 7) / 8));
    norx_absorb_data(state, z, zlen, tag_t.TRAILER_TAG);
    norx_finalise(state, tag, k);
    *mlen = clen - ((((64 * 4)) + 7) / 8);

    result = norx_verify_tag(c + clen - ((((64 * 4)) + 7) / 8), tag);
    if (result != 0) { /* burn decrypted plaintext on auth failure */
        memset(m, 0, clen - ((((64 * 4)) + 7) / 8));
    }
    *state = default(norx_state_t);
    memset(k, 0, ((((64 * 4)) + 7) / 8));
    return result;
}

}
}




internal static partial class Interop
{
    internal static partial class Norx6441
    {
        internal const int crypto_aead_norx6441_KEYBYTES = 32;
        internal const int crypto_aead_norx6441_NSECBYTES = 0;
        internal const int crypto_aead_norx6441_NPUBBYTES = 32;
        internal const int crypto_aead_norx6441_ABYTES = 32;

        internal static unsafe int crypto_aead_norx6441_encrypt(
            ref byte c,
            out ulong clen,
            ref byte m,
            ulong mlen,
            ref byte ad,
            ulong adlen,
            IntPtr nsec,
            ref byte npub,
            SecureMemoryHandle k)
        {
            fixed (byte* _c = &c)
            fixed (byte* _m = &m)
            fixed (byte* _ad = &ad)
            fixed (byte* _npub = &npub)
            {
                ulong outlen = 0;
                norx_aead_encrypt(_c, &outlen, _ad, adlen, _m, mlen, null, 0, _npub, (byte*)k.DangerousGetHandle());
                clen = outlen;
                return 0;
            }
        }

        internal static unsafe int crypto_aead_norx6441_decrypt(
            ref byte m,
            out ulong mlen,
            IntPtr nsec,
            ref byte c,
            ulong clen,
            ref byte ad,
            ulong adlen,
            ref byte npub,
            SecureMemoryHandle k)
        {
            fixed (byte* _m = &m)
            fixed (byte* _c = &c)
            fixed (byte* _ad = &ad)
            fixed (byte* _npub = &npub)
            {
                ulong outlen = 0;
                int result = norx_aead_decrypt(_m, &outlen, _ad, adlen, _c, clen, null, 0, _npub, (byte*)k.DangerousGetHandle());
                mlen = outlen;
                return result;
            }
        }
    }
}
