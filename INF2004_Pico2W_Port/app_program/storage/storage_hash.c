/** @file storage_hash.c
 * @brief SHA-256 using a 16-word rolling schedule; no hardware/IRQ/TLS owner.
 * FIPS 180-4 algorithm. The digest detects changed bytes; it is not a
 * signature.
 */
#include "storage_hash.h"
#include <string.h>
static const uint32_t g_constants[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
    0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
    0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
    0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
    0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
    0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
    0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
    0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
    0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
    0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u};
static uint32_t
storage_rotr (uint32_t x, unsigned n)
{
    return (x >> n) | (x << (32u - n));
}
static void
storage_hash_block (storage_hash_t * p)
{
    uint32_t w[16];
    uint32_t a = p->words[0], b = p->words[1], c = p->words[2], d = p->words[3];
    uint32_t e = p->words[4], f = p->words[5], g = p->words[6], h = p->words[7];
    for (size_t i = 0u; i < 16u; i++)
    {
        const uint8_t * q = &p->block[i * 4u];
        w[i]              = ((uint32_t) q[0] << 24u) | ((uint32_t) q[1] << 16u)
                          | ((uint32_t) q[2] << 8u) | q[3];
    }
    for (unsigned i = 0u; i < 64u; i++)
    {
        unsigned j = i & 15u;
        if (i >= 16u)
        {
            uint32_t x = w[(i + 1u) & 15u], y = w[(i + 14u) & 15u];
            uint32_t s0 =
                storage_rotr(x, 7u) ^ storage_rotr(x, 18u) ^ (x >> 3u);
            uint32_t s1 =
                storage_rotr(y, 17u) ^ storage_rotr(y, 19u) ^ (y >> 10u);
            w[j] += s0 + w[(i + 9u) & 15u] + s1;
        }
        uint32_t sum1 =
            storage_rotr(e, 6u) ^ storage_rotr(e, 11u) ^ storage_rotr(e, 25u);
        uint32_t choose = (e & f) ^ ((~e) & g);
        uint32_t t1     = h + sum1 + choose + g_constants[i] + w[j];
        uint32_t sum0 =
            storage_rotr(a, 2u) ^ storage_rotr(a, 13u) ^ storage_rotr(a, 22u);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2       = sum0 + majority;
        h                 = g;
        g                 = f;
        f                 = e;
        e                 = d + t1;
        d                 = c;
        c                 = b;
        b                 = a;
        a                 = t1 + t2;
    }
    p->words[0] += a;
    p->words[1] += b;
    p->words[2] += c;
    p->words[3] += d;
    p->words[4] += e;
    p->words[5] += f;
    p->words[6] += g;
    p->words[7] += h;
}
void
storage_hash_init (storage_hash_t * p)
{
    static const uint32_t initial[8] = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u,
                                        0xa54ff53au, 0x510e527fu, 0x9b05688cu,
                                        0x1f83d9abu, 0x5be0cd19u};
    memcpy(p->words, initial, sizeof(initial));
    p->bytes = 0u;
    p->used  = 0u;
}
void
storage_hash_update (storage_hash_t * p, const uint8_t * data, size_t length)
{
    p->bytes += length;
    while (length > 0u)
    {
        size_t n = 64u - p->used;
        if (n > length)
        {
            n = length;
        }
        memcpy(p->block + p->used, data, n);
        p->used += n;
        data += n;
        length -= n;
        if (p->used == 64u)
        {
            storage_hash_block(p);
            p->used = 0u;
        }
    }
}
void
storage_hash_finish (storage_hash_t * p, uint8_t digest[32])
{
    uint64_t bits       = p->bytes * 8u;
    p->block[p->used++] = 0x80u;
    if (p->used > 56u)
    {
        memset(p->block + p->used, 0, 64u - p->used);
        storage_hash_block(p);
        p->used = 0u;
    }
    memset(p->block + p->used, 0, 56u - p->used);
    for (unsigned i = 0u; i < 8u; i++)
    {
        p->block[63u - i] = (uint8_t) (bits >> (i * 8u));
    }
    storage_hash_block(p);
    for (unsigned i = 0u; i < 32u; i++)
    {
        digest[i] = (uint8_t) (p->words[i / 4u] >> (24u - 8u * (i & 3u)));
    }
}
/*** end of file ***/
