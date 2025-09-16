#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Right rotate x by n bits */
static inline uint32_t rotr(uint32_t x, unsigned n) {
    return (x >> n) | (x << (32 - n));
}

/* SHA-256 helper macros (spec functions) */
#define CH(x,y,z)  ((x & y) ^ (~x & z))
#define MAJ(x,y,z) ((x & y) ^ (x & z) ^ (y & z))
#define SIG0(x)    (rotr(x, 2) ^ rotr(x,13) ^ rotr(x,22))
#define SIG1(x)    (rotr(x, 6) ^ rotr(x,11) ^ rotr(x,25))
#define sigma0(x)  (rotr(x, 7) ^ rotr(x,18) ^ (x >> 3))
#define sigma1(x)  (rotr(x,17) ^ rotr(x,19) ^ (x >> 10))

/* SHA-256 constants K (first 32 bits of the fractional parts of the cube roots of the first 64 primes) */
static const uint32_t K[64] = {
  0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,0x3956c25bUL,0x59f111f1UL,0x923f82a4UL,0xab1c5ed5UL,
  0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,
  0xe49b69c1UL,0xefbe4786UL,0x0fc19dc6UL,0x240ca1ccUL,0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
  0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,0xc6e00bf3UL,0xd5a79147UL,0x06ca6351UL,0x14292967UL,
  0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,
  0xa2bfe8a1UL,0xa81a664bUL,0xc24b8b70UL,0xc76c51a3UL,0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
  0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,0x391c0cb3UL,0x4ed8aa4aUL,0x5b9cca4fUL,0x682e6ff3UL,
  0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL
};

/* Initial hash values H0..H7 (first 32 bits of the fractional parts of the square roots of the first 8 primes) */
static const uint32_t H0_init[8] = {
  0x6a09e667UL,0xbb67ae85UL,0x3c6ef372UL,0xa54ff53aUL,
  0x510e527fUL,0x9b05688cUL,0x1f83d9abUL,0x5be0cd19UL
};

/* Convert 4 bytes (big-endian) to a 32-bit word */
static uint32_t be32(const unsigned char *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | ((uint32_t)b[3]);
}

/* Convert 32-bit word to 4 bytes big-endian */
static void to_be32(uint32_t v, unsigned char *out) {
    out[0] = (unsigned char)(v >> 24);
    out[1] = (unsigned char)(v >> 16);
    out[2] = (unsigned char)(v >> 8);
    out[3] = (unsigned char)(v & 0xFF);
}

/*
 * Compute SHA-256 digest for a message (input, input_len bytes).
 * digest must point to a buffer of at least 32 bytes.
 */
void sha256(const unsigned char *input, size_t input_len, unsigned char *digest) {
    // 1) Calculate padded message length:
    //    message + 1 bit (0x80) + k zero bytes + 8 bytes length = multiple of 64 bytes
    uint64_t bitlen = (uint64_t)input_len * 8ULL;
    size_t pad_len = 1 + 8; // at least 1 byte (0x80) and 8 bytes length
    // compute additional zeros needed so (input_len + pad_len + zeros) % 64 == 0
    size_t total_len = input_len + pad_len;
    size_t rem = total_len % 64;
    size_t add = (rem == 0) ? 0 : (64 - rem);
    size_t full_len = total_len + add;

    unsigned char *msg = (unsigned char*)malloc(full_len);
    if (!msg) {
        fprintf(stderr, "Out of memory\n");
        exit(1);
    }

    // copy original message
    memcpy(msg, input, input_len);
    // append 0x80 (1000 0000)
    msg[input_len] = 0x80;
    // zero padding (add - 1 zeros already included if any)
    if (add > 0) memset(msg + input_len + 1, 0, add);
    // place 64-bit big-endian length at the last 8 bytes
    // note: big-endian -> high-order bytes first
    for (int i = 0; i < 8; ++i) {
        msg[full_len - 8 + i] = (unsigned char)((bitlen >> (8*(7 - i))) & 0xFF);
    }

    // 2) Initialize working variables with initial hash values
    uint32_t H[8];
    for (int i = 0; i < 8; ++i) H[i] = H0_init[i];

    // 3) Process the message in 512-bit (64-byte) chunks
    size_t num_chunks = full_len / 64;
    for (size_t chunk = 0; chunk < num_chunks; ++chunk) {
        const unsigned char *block = msg + (chunk * 64);

        // Prepare message schedule W[0..63]
        uint32_t W[64];
        for (int t = 0; t < 16; ++t) {
            W[t] = be32(block + t*4); // big-endian words from block
        }
        for (int t = 16; t < 64; ++t) {
            W[t] = sigma1(W[t-2]) + W[t-7] + sigma0(W[t-15]) + W[t-16];
        }

        // Initialize a..h to current hash value
        uint32_t a = H[0];
        uint32_t b = H[1];
        uint32_t c = H[2];
        uint32_t d = H[3];
        uint32_t e = H[4];
        uint32_t f = H[5];
        uint32_t g = H[6];
        uint32_t h = H[7];

        // Main compression function — 64 rounds
        for (int t = 0; t < 64; ++t) {
            uint32_t T1 = h + SIG1(e) + CH(e,f,g) + K[t] + W[t];
            uint32_t T2 = SIG0(a) + MAJ(a,b,c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }

        // Add the compressed chunk to the current hash value
        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    // produce final digest (big-endian)
    for (int i = 0; i < 8; ++i) {
        to_be32(H[i], digest + i*4);
    }

    free(msg);
}

/* Helper to print digest as hex */
void print_hex(const unsigned char *digest, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        printf("%02x", digest[i]);
    }
    printf("\n");
}

/* Main — read input string from argv[1] (or prompt) and print SHA-256 */
int main(int argc, char *argv[]) {
    const char *message;
    if (argc >= 2) {
        message = argv[1];
    } else {
         message = "Blockchain Cryptography"; 
    }

    unsigned char digest[32];
    sha256((const unsigned char*)message, strlen(message), digest);

    printf("SHA-256(\"%s\") = ", message);
    print_hex(digest, 32);

    return 0;
}
