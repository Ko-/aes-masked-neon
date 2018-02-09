#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "common.h"

#define NUM_TESTS 10000

unsigned long long results[NUM_TESTS];

extern void aes_keyexp(bint16_t key[8], bint16_t rk[11][8 * NUM_BLOCKS]);
extern void aes_enc(FILE * random, bint16_t rk[11][8 * NUM_BLOCKS], bint16_t state[8 * NUM_BLOCKS]);

int main (void) {
    unsigned int i, j;
    unsigned long long time;
    bint16_t input_shared[8 * NUM_BLOCKS] __attribute((aligned(16)));
    bint16_t key_shared[8];
    bint16_t roundkeys_shared[11][8 * NUM_BLOCKS] __attribute__((aligned(16)));

    uint16_t roundkeys[11][8] =  {{0x0405, 0x0607, 0x0405, 0x0608, 0x0405, 0x0609, 0x0405, 0x060a},
                                  {0x6e6a, 0x61f5, 0x6a6f, 0x67fd, 0x6e6a, 0x61f4, 0x6a6f, 0x67fe},
                                  {0xc4ef, 0xdaf7, 0xae80, 0xbd0a, 0xc0ea, 0xdcfe, 0xaa85, 0xbb00},
                                  {0x5705, 0xb95b, 0xf985, 0x0451, 0x396f, 0xd8af, 0x93ea, 0x63af},
                                  {0xd8fe, 0xc087, 0x217b, 0xc4d6, 0x1814, 0x1c79, 0x8bfe, 0x7fd6},
                                  {0x732c, 0x36ba, 0x5257, 0xf26c, 0x4a43, 0xee15, 0xc1bd, 0x91c3},
                                  {0x29ad, 0x18c2, 0x7bfa, 0xeaae, 0x31b9, 0x04bb, 0xf004, 0x9578},
                                  {0x9b87, 0xa44e, 0xe07d, 0x4ee0, 0xd1c4, 0x4a5b, 0x21c0, 0xdf23},
                                  {0xa119, 0x82b3, 0x4164, 0xcc53, 0x90a0, 0x8608, 0xb160, 0x592b},
                                  {0x6ad2, 0x737b, 0x2bb6, 0xbf28, 0xbb16, 0x3920, 0x0a76, 0x600b},
                                  {0x6402, 0x581c, 0x4fb4, 0xe734, 0xf4a2, 0xde14, 0xfed4, 0xbe1f}};
    
    uint16_t input[8 * NUM_BLOCKS];
    for (i = 0; i < 8 * NUM_BLOCKS; i++)
        input[i] = (2 * i << 8) | (2 * i + 1);

    // change to /dev/zero to 'disable' randomness
    FILE * random = fopen("/dev/urandom", "rb");

    printf("Encrypting plaintext\n");
    printdata(input, NUM_BLOCKS);

    printf("Under key\n");
    printdata(roundkeys[0], 1);

    // share the message and the round keys
    for (i = 0; i < 8; i++) {
        for (j = 0; j < 11; j++) {
            share_secret(roundkeys_shared[j][i], roundkeys[j][i], random); 
        }
    }      
    for (i = 0; i < 8 * NUM_BLOCKS; i++) {
        share_secret(input_shared[i], input[i], random);
    }      

    // for now, this just bitslices the round keys and performs some NOTs to be compensated by SubBytes
    aes_keyexp(key_shared, roundkeys_shared);

    /*
    printf("Under round keys\n");
    for (i = 0; i < 11; i++) {
        for (j = 0; j < 8; j++) {
            key[i][j] = recombine_share_key(roundkeys_shared[i][j*NUM_BLOCKS], roundkeys_shared[i][j*NUM_BLOCKS+1]);
        }
        printdata(key[i], 1);
    }
    */
   
    // do NUM_TESTS measurements and take median
    for (i = 0; i < NUM_TESTS; i++) {
        time = cpucycles_cortex();
        aes_enc(random, roundkeys_shared, input_shared);
        results[i] = cpucycles_cortex() - time;
    }

    qsort(results, NUM_TESTS, sizeof(unsigned long long), compare);

    for (i = 0; i < 8 * NUM_BLOCKS; i++) {
        input[i] = recombine_share(input_shared[i]);
    }

    printf("Yields ciphertext\n");
    printdata(input, NUM_BLOCKS);

    printf("In %llu cycles\n", results[NUM_TESTS/2]);

    return 0;
}
