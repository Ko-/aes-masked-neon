#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include "common.h"

// Pin-layout:
// P9_1  = GND
// P9_27 = GPIO3_19, used for triggering

extern void aes_keyexp(bint16_t key_shared[8], bint16_t roundkeys_shared[11][8 * NUM_BLOCKS]);
extern void aes_enc(FILE * random, bint16_t roundkeys_shared[11][8 * NUM_BLOCKS], bint16_t input_shared[8 * NUM_BLOCKS], int fdtrigger);

void triggerup(const int fd) {
    if(!fd)
        return;
    const char one = '1';
    write(fd, &one, 1);
}

void triggerdown(const int fd) {
    if(!fd)
        return;
    const char zero = '0';
    write(fd, &zero, 1);
}

int main (int argc, char** argv) {
    unsigned int i, j;
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
    
    uint16_t input[8 * NUM_BLOCKS] = {0};

    // read input from argv[1]
    if(argc < 2)
        return -1;
    const char *pos = argv[1];
    size_t count = 0;
    for (count = 0; count < 8 * NUM_BLOCKS; count++) {
        sscanf(pos, "%4hx", &input[count]);
        pos += 4;
    }

    // change to /dev/zero to 'disable' randomness
    FILE * random = fopen("/dev/urandom", "rb");

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

    // prepare pin P9_27 for triggering
    struct stat sb;
    int res, fd;
    (void)res;
    if (stat("/sys/class/gpio/gpio115", &sb) != 0 || !S_ISDIR(sb.st_mode)) {
        res = system("echo 115 > /sys/class/gpio/export");
    }
    res = system("echo low > /sys/class/gpio/gpio115/direction");
    fd = open("/sys/class/gpio/gpio115/value", O_WRONLY);

    // first execute without measuring to fill caches
    long long time = cpucycles_cortex();
    for (i = 0; i < 1000; i++)
        aes_enc(random, roundkeys_shared, input_shared, 0);
    // now measure!
    aes_enc(random, roundkeys_shared, input_shared, fd);
    time = cpucycles_cortex() - time;

    // recombine shares and write back output
    for (i = 0; i < 8; i++) {
        input[i] = recombine_share(input_shared[i]);
        printf("%04x", input[i]);
    }

    printf("\nIn %llu cycles\n", time);

    return 0;
}
