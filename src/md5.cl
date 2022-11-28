__constant uint T[64] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8,
    0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193,
    0xa679438e, 0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51,
    0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905,
    0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681,
    0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60,
    0xbebfbc70, 0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244,
    0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92,
    0xffeff47d, 0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314,
    0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

/*  
  ***************
  *FROM RFC 1321*
  ***************
*/

// F, G, H and I are basic MD5 functions.
inline uint F(uint x, uint y, uint z) { 
    return (x & y) | (~x & z);
}
inline uint G(uint x, uint y, uint z) {
    return (x & z) | (y & ~z);
}
inline uint H(uint x, uint y, uint z) {
    return x ^ y ^ z;
}
inline uint I(uint x, uint y, uint z) {
    return y ^ (x | ~z);
}
// ROTATE_LEFT rotates x left n bits.
inline uint ROTATE_LEFT(uint x, uint n) {
    return (x << n) | (x >> (32-n));
}

// FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
// Rotation is separate from addition to prevent recomputation.
inline uint FF(uint a, uint b, uint c, uint d, uint x, uint s, uint t) {
    a += F(b, c, d) + x + t;
    a = ROTATE_LEFT(a, s);
    return a + b;
}
inline uint GG(uint a, uint b, uint c, uint d, uint x, uint s, uint t) {
    a += G(b, c, d) + x + t;
    a = ROTATE_LEFT(a, s);
    return a + b;
}
inline uint HH(uint a, uint b, uint c, uint d, uint x, uint s, uint t) {
    a += H(b, c, d) + x + t;
    a = ROTATE_LEFT(a, s);
    return a + b;
}
inline uint II(uint a, uint b, uint c, uint d, uint x, uint s, uint t) {
    a += I(b, c, d) + x + t;
    a = ROTATE_LEFT(a, s);
    return a + b;
}

inline uint SWAP_UINT32(n) {
    return ((n & 0xff000000) >> 24)
         + ((n & 0x00ff0000) >>  8)
         + ((n & 0x0000ff00) <<  8)
         + ((n & 0x000000ff) << 24);
}

uint4 generate_md5_digest(uchar *msg, const uint length) {
    // 3.1 Step 1. Append Padding Bits
    size_t padding_length = length;
    msg[padding_length] = 0x80;
    padding_length++;
    while (padding_length % 64 != 56) {
        msg[padding_length] = 0x00;
        padding_length++;
    }

    // 3.2 Step 2. Append Length
    ulong bit_length = length * 8;
    msg[padding_length + 7] = (bit_length >> 56) & 0xff;
    msg[padding_length + 6] = (bit_length >> 48) & 0xff;
    msg[padding_length + 5] = (bit_length >> 40) & 0xff;
    msg[padding_length + 4] = (bit_length >> 32) & 0xff;
    msg[padding_length + 3] = (bit_length >> 24) & 0xff;
    msg[padding_length + 2] = (bit_length >> 16) & 0xff;
    msg[padding_length + 1] = (bit_length >> 8)  & 0xff;
    msg[padding_length    ] = (bit_length)       & 0xff;
    padding_length += 8;

    uint *M = msg;
    size_t M_length = padding_length / 4;

    // printf("(len-%d) %c%c%c ... %02x%02x%02x%02x\n", length, msg[0], msg[1], msg[2], msg[padding_length-8], msg[padding_length-7], msg[padding_length-6], msg[padding_length-5]);

    // 3.3 Step 3. Initialize MD Buffer
    uint A = 0x67452301;
    uint B = 0xefcdab89;
    uint C = 0x98badcfe;
    uint D = 0x10325476;

    // 3.4 Step 4. Process Message in 16-Word Blocks
    for (size_t i = 0; i < M_length / 16; ++i){
        // Copy block into X.
        uint *X = M + i*16;

        // Save A as AA, B as BB, C as CC, and D as DD.
        uint AA = A;
        uint BB = B;
        uint CC = C;
        uint DD = D;

        // Round 1.
        AA = FF(AA, BB, CC, DD, X[ 0],  7, T[ 0]);
        DD = FF(DD, AA, BB, CC, X[ 1], 12, T[ 1]);
        CC = FF(CC, DD, AA, BB, X[ 2], 17, T[ 2]);
        BB = FF(BB, CC, DD, AA, X[ 3], 22, T[ 3]);
        AA = FF(AA, BB, CC, DD, X[ 4],  7, T[ 4]);
        DD = FF(DD, AA, BB, CC, X[ 5], 12, T[ 5]);
        CC = FF(CC, DD, AA, BB, X[ 6], 17, T[ 6]);
        BB = FF(BB, CC, DD, AA, X[ 7], 22, T[ 7]);
        AA = FF(AA, BB, CC, DD, X[ 8],  7, T[ 8]);
        DD = FF(DD, AA, BB, CC, X[ 9], 12, T[ 9]);
        CC = FF(CC, DD, AA, BB, X[10], 17, T[10]);
        BB = FF(BB, CC, DD, AA, X[11], 22, T[11]);
        AA = FF(AA, BB, CC, DD, X[12],  7, T[12]);
        DD = FF(DD, AA, BB, CC, X[13], 12, T[13]);
        CC = FF(CC, DD, AA, BB, X[14], 17, T[14]);
        BB = FF(BB, CC, DD, AA, X[15], 22, T[15]);
        // printf("%c%c%c: (i = %d) %04x, %04x, %04x, %04x\n", msg[0], msg[1], msg[2], i, AA, BB, CC, DD);

        // Round 2.
        AA = GG(AA, BB, CC, DD, X[ 1],  5, T[16]);
        DD = GG(DD, AA, BB, CC, X[ 6],  9, T[17]);
        CC = GG(CC, DD, AA, BB, X[11], 14, T[18]);
        BB = GG(BB, CC, DD, AA, X[ 0], 20, T[19]);
        AA = GG(AA, BB, CC, DD, X[ 5],  5, T[20]);
        DD = GG(DD, AA, BB, CC, X[10],  9, T[21]);
        CC = GG(CC, DD, AA, BB, X[15], 14, T[22]);
        BB = GG(BB, CC, DD, AA, X[ 4], 20, T[23]);
        AA = GG(AA, BB, CC, DD, X[ 9],  5, T[24]);
        DD = GG(DD, AA, BB, CC, X[14],  9, T[25]);
        CC = GG(CC, DD, AA, BB, X[ 3], 14, T[26]);
        BB = GG(BB, CC, DD, AA, X[ 8], 20, T[27]);
        AA = GG(AA, BB, CC, DD, X[13],  5, T[28]);
        DD = GG(DD, AA, BB, CC, X[ 2],  9, T[29]);
        CC = GG(CC, DD, AA, BB, X[ 7], 14, T[30]);
        BB = GG(BB, CC, DD, AA, X[12], 20, T[31]);
        // printf("%c%c%c: (i = %d) %04x, %04x, %04x, %04x\n", msg[0], msg[1], msg[2], i, AA, BB, CC, DD);

        // Round 3.
        AA = HH(AA, BB, CC, DD, X[ 5],  4, T[32]);
        DD = HH(DD, AA, BB, CC, X[ 8], 11, T[33]);
        CC = HH(CC, DD, AA, BB, X[11], 16, T[34]);
        BB = HH(BB, CC, DD, AA, X[14], 23, T[35]);
        AA = HH(AA, BB, CC, DD, X[ 1],  4, T[36]);
        DD = HH(DD, AA, BB, CC, X[ 4], 11, T[37]);
        CC = HH(CC, DD, AA, BB, X[ 7], 16, T[38]);
        BB = HH(BB, CC, DD, AA, X[10], 23, T[39]);
        AA = HH(AA, BB, CC, DD, X[13],  4, T[40]);
        DD = HH(DD, AA, BB, CC, X[ 0], 11, T[41]);
        CC = HH(CC, DD, AA, BB, X[ 3], 16, T[42]);
        BB = HH(BB, CC, DD, AA, X[ 6], 23, T[43]);
        AA = HH(AA, BB, CC, DD, X[ 9],  4, T[44]);
        DD = HH(DD, AA, BB, CC, X[12], 11, T[45]);
        CC = HH(CC, DD, AA, BB, X[15], 16, T[46]);
        BB = HH(BB, CC, DD, AA, X[ 2], 23, T[47]);
        // printf("%c%c%c: (i = %d) %04x, %04x, %04x, %04x\n", msg[0], msg[1], msg[2], i, AA, BB, CC, DD);

        // Round 4.
        AA = II(AA, BB, CC, DD, X[ 0],  6, T[48]);
        DD = II(DD, AA, BB, CC, X[ 7], 10, T[49]);
        CC = II(CC, DD, AA, BB, X[14], 15, T[50]);
        BB = II(BB, CC, DD, AA, X[ 5], 21, T[51]);
        AA = II(AA, BB, CC, DD, X[12],  6, T[52]);
        DD = II(DD, AA, BB, CC, X[ 3], 10, T[53]);
        CC = II(CC, DD, AA, BB, X[10], 15, T[54]);
        BB = II(BB, CC, DD, AA, X[ 1], 21, T[55]);
        AA = II(AA, BB, CC, DD, X[ 8],  6, T[56]);
        DD = II(DD, AA, BB, CC, X[15], 10, T[57]);
        CC = II(CC, DD, AA, BB, X[ 6], 15, T[58]);
        BB = II(BB, CC, DD, AA, X[13], 21, T[59]);
        AA = II(AA, BB, CC, DD, X[ 4],  6, T[60]);
        DD = II(DD, AA, BB, CC, X[11], 10, T[61]);
        CC = II(CC, DD, AA, BB, X[ 2], 15, T[62]);
        BB = II(BB, CC, DD, AA, X[ 9], 21, T[63]);
        // printf("%c%c%c: (i = %d) %04x, %04x, %04x, %04x\n", msg[0], msg[1], msg[2], i, AA, BB, CC, DD);

        A += AA;
        B += BB;
        C += CC;
        D += DD;
        // printf("%c%c%c: (i = %d) %04x, %04x, %04x, %04x\n", msg[0], msg[1], msg[2], i, A, B, C, D);
    }

    return (uint4)(A, B, C, D);
}

// Generates an MD5 digest for each 128-byte message
__kernel void generate_md5_digests(__global const uchar *messages, __global const uint *lengths, __global uint *results) {
    size_t gid = get_global_id(0);

    // Determine base index and length of the assigned message
    uint length;
    uint msg_start;
    if (gid > 0)
        msg_start = lengths[gid - 1];
    else
        msg_start = 0;
    length = lengths[gid] - msg_start;

    // Extract the assigned message from the input buffer
    uchar msg[128] = {0};
    for (size_t i = 0; i < length; ++i){
        msg[i] = messages[msg_start + i];
    }

    // Compute the MD5 digest for this password
    uint4 result_digest = generate_md5_digest(msg, length);
    
    // Store the results
    results[gid * 4]     = result_digest.s0;
    results[gid * 4 + 1] = result_digest.s1;
    results[gid * 4 + 2] = result_digest.s2;
    results[gid * 4 + 3] = result_digest.s3;
}

// Determines if ANY of the given messages matches the given target_digest
__kernel void bruteforce_md5_digests(
    __global const uchar *messages, 
    __global const uint  *lengths,
             const uint4 target_digest,
    __global       uint  *global_result ) // Output array of length 1
{
    size_t gid = get_global_id(0);
    
    // Determine base index and length of the assigned message
    uint length;
    uint msg_start;
    if (gid > 0)
        msg_start = lengths[gid - 1];
    else
        msg_start = 0;
    length = lengths[gid] - msg_start;

    // Extract the assigned message from the input buffer
    uchar msg[128] = {0};
    for (size_t i = 0; i < length; ++i){
        msg[i] = messages[msg_start + i];
    }

    // Compute the MD5 digest for this password
    uint4 result_digest = generate_md5_digest(msg, length);

    // If our MD5 digest matches the target digest, set the result to our GID + 1.
    //   - The +1 ensures that work-item 0 is also able to report success
    //   - Assumes only ONE password in this set will be correct.
    if (   result_digest.s0 == target_digest.s0 
        && result_digest.s1 == target_digest.s1
        && result_digest.s2 == target_digest.s2
        && result_digest.s3 == target_digest.s3) {
        global_result[0] = gid + 1;
        // printf("%d: %c%c ... %c%c\n", gid, msg[0], msg[1], msg[lengths[gid]-2], msg[lengths[gid]-1]);
        // printf("Result: %04x, %04x, %04x, %04x - Target: %04x, %04x, %04x, %04x\n",
        //     result_digest.s0, result_digest.s1, result_digest.s2, result_digest.s3,
        //     target_digest.s0, target_digest.s1, target_digest.s2, target_digest.s3);
    }
}