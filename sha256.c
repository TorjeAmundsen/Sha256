/*

SHA-256 in C, implementation by Torje Amundsen
Following pseudocode from https://en.wikipedia.org/wiki/SHA-2#Pseudocode
Comments mostly from this pseudocode

*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ROR(num, count) (((num) >> (count)) | ((num) << (32 - (count))))

typedef unsigned char Byte;
typedef unsigned int Word;

typedef struct {
    Byte *pre_processed;
    Word pre_processed_len;
    Word hash_state[8];
} sha256_ctx;

// (first 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
static const Word k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

void sha256_initCtx(sha256_ctx *ctx) {
    ctx->pre_processed_len = 0;
    ctx->pre_processed = NULL;

    // first 32 bits of the fractional parts of the square roots of the first 8 primes (2...19)
    ctx->hash_state[0] = 0x6a09e667;
	ctx->hash_state[1] = 0xbb67ae85;
	ctx->hash_state[2] = 0x3c6ef372;
	ctx->hash_state[3] = 0xa54ff53a;
	ctx->hash_state[4] = 0x510e527f;
	ctx->hash_state[5] = 0x9b05688c;
	ctx->hash_state[6] = 0x1f83d9ab;
	ctx->hash_state[7] = 0x5be0cd19;
}

void sha256_pre_process(sha256_ctx *ctx, const Byte input[], Word inputLen) {
    int i;
    Word arr_bitlen = 512;
    int K = arr_bitlen - 65 - (inputLen * 8);
    while (K < 0) {
        arr_bitlen += 512;
        K = arr_bitlen - 65 - (inputLen * 8);
    }

    arr_bitlen = (inputLen * 8) + 1 + K + 64;
    
    Word len = arr_bitlen / 8;
    Byte *arr = malloc(len);

    for (i = 0; i < inputLen; ++i) {
        arr[i] = input[i];
    }
    for (i = inputLen; i < len; ++i) {
        arr[i] = 0U;
    }
    arr[inputLen] = 128U;

    unsigned long long input_bitlen = (unsigned long long)inputLen;

    arr[len - 1] = (input_bitlen * 8) & 0xff;
    arr[len - 2] = ((input_bitlen * 8) >> 8) & 0xff;
    arr[len - 3] = ((input_bitlen * 8) >> 16) & 0xff;
    arr[len - 4] = ((input_bitlen * 8) >> 24) & 0xff;
    arr[len - 5] = ((input_bitlen * 8) >> 32) & 0xff;
    arr[len - 6] = ((input_bitlen * 8) >> 40) & 0xff;
    arr[len - 7] = ((input_bitlen * 8) >> 48) & 0xff;
    arr[len - 8] = ((input_bitlen * 8) >> 56) & 0xff;

    ctx->pre_processed = arr;
    ctx->pre_processed_len = len;
}

void sha256_scramble(sha256_ctx *ctx, Word chunkOffset) {
    Word a, b, c, d, e, f, g, h, i, j, temp1, temp2;
    Word words[64] = {0};

    for (i = 0, j = 0; i < 16; ++i, j += 4) {

        // writes 4 bytes from ctx->preprocessed into one word in words[]
        words[i] = (ctx->pre_processed[j +     chunkOffset] << 24) |
                   (ctx->pre_processed[j + 1 + chunkOffset] << 16) |
                   (ctx->pre_processed[j + 2 + chunkOffset] << 8 ) |
                   (ctx->pre_processed[j + 3 + chunkOffset]      );
    }

    for (; i < 64; ++i) {
        Word s0 = (ROR(words[i - 15], 7)) ^ (ROR(words[i - 15], 18)) ^ ((words[i - 15]) >> 3);
        Word s1 = (ROR(words[i - 2], 17)) ^ (ROR(words[i - 2], 19)) ^ ((words[i - 2] >> 10));
        words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }

    a = ctx->hash_state[0];
    b = ctx->hash_state[1];
    c = ctx->hash_state[2];
    d = ctx->hash_state[3];
    e = ctx->hash_state[4];
    f = ctx->hash_state[5];
    g = ctx->hash_state[6];
    h = ctx->hash_state[7];
    
    // main compression loop (sorcery)
    for (i = 0; i < 64; ++i) {
        Word S1 = (ROR(e, 6)) ^ (ROR(e, 11)) ^ (ROR(e, 25));
        Word ch = (e & f) ^ ((~ e) & g);
        temp1 = h + S1 + ch + k[i] + words[i];
        Word S0 = (ROR(a, 2)) ^ (ROR(a, 13)) ^ (ROR(a, 22));
        Word maj = (a & b) ^ (a & c) ^ (b & c);
        temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx->hash_state[0] = ctx->hash_state[0] + a;
    ctx->hash_state[1] = ctx->hash_state[1] + b;
    ctx->hash_state[2] = ctx->hash_state[2] + c;
    ctx->hash_state[3] = ctx->hash_state[3] + d;
    ctx->hash_state[4] = ctx->hash_state[4] + e;
    ctx->hash_state[5] = ctx->hash_state[5] + f;
    ctx->hash_state[6] = ctx->hash_state[6] + g;
    ctx->hash_state[7] = ctx->hash_state[7] + h;
}

void sha256_complete(const Byte input[]) {
    Word i;
    Word inputLen = strlen(input);
    sha256_ctx *ctx = malloc(sizeof(sha256_ctx));

    sha256_initCtx(ctx);
    sha256_pre_process(ctx, input, inputLen);

    // scrambles for each 512 bit (64 byte) chunk of the pre-processed message
    for (i = 0; i < ctx->pre_processed_len / 64; ++i) {
        sha256_scramble(ctx, i * 64);
    }

    for (i = 0; i < 8; ++i) {
        printf("%08x", ctx->hash_state[i]);
    }

    printf("\n");

    // look mom im writing C lol
    free(ctx->pre_processed);
    free(ctx);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Warning: No input given. Running SHA-256 with an empty string...\n\n");
        sha256_complete("");
    }
    else {
        sha256_complete(argv[1]);
    }
    return 0;
}